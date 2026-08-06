import { gzipSync } from "node:zlib";
import { Octokit } from "@octokit/rest";
import type { Config } from "./config.js";
import type { SarifLog, SarifResult } from "./types.js";

type AnalysisSummary = {
  id: number;
  ref: string;
  commit_sha: string;
  category?: string;
  analysis_key?: string;
  created_at: string;
  tool?: { name?: string };
};

type AlertSummary = {
  number: number;
  most_recent_instance?: { commit_sha?: string };
};

function alertNumber(result: SarifResult): number | null {
  const candidate = result.properties?.["github/alertNumber"];
  if (typeof candidate === "number" && Number.isInteger(candidate)) return candidate;
  if (typeof candidate === "string" && /^\d+$/.test(candidate)) return Number(candidate);
  return null;
}

function isSarifLog(value: unknown): value is SarifLog {
  return Boolean(
    value &&
      typeof value === "object" &&
      (value as { version?: unknown }).version === "2.1.0" &&
      Array.isArray((value as { runs?: unknown }).runs),
  );
}

export class GitHubCodeScanning {
  private readonly octokit: Octokit;

  constructor(private readonly config: Config) {
    this.octokit = new Octokit({
      auth: config.githubToken,
      userAgent: "codex-security-consolidator/0.1.0",
    });
  }

  async downloadOpenCodeqlSarif(): Promise<SarifLog> {
    const analysesResponse = await this.octokit.request(
      "GET /repos/{owner}/{repo}/code-scanning/analyses",
      {
        owner: this.config.owner,
        repo: this.config.repo,
        tool_name: "CodeQL",
        ref: this.config.ref,
        per_page: 100,
        headers: { "X-GitHub-Api-Version": "2026-03-10" },
      },
    );
    const analyses = analysesResponse.data as AnalysisSummary[];
    const matching = analyses.filter(
      (analysis) => analysis.commit_sha === this.config.sha && analysis.ref === this.config.ref,
    );
    if (matching.length === 0) {
      throw new Error(
        `No CodeQL analysis exists for ${this.config.ref}@${this.config.sha}. Run CodeQL and responsibility 1 for this exact commit before responsibilities 2 and 3.`,
      );
    }

    const latestByCategory = new Map<string, AnalysisSummary>();
    for (const analysis of matching) {
      const category = analysis.category || analysis.analysis_key || String(analysis.id);
      const previous = latestByCategory.get(category);
      if (!previous || Date.parse(analysis.created_at) > Date.parse(previous.created_at)) {
        latestByCategory.set(category, analysis);
      }
    }

    const alerts: AlertSummary[] = [];
    for (let page = 1; ; page += 1) {
      const pageResponse = await this.octokit.request("GET /repos/{owner}/{repo}/code-scanning/alerts", {
        owner: this.config.owner,
        repo: this.config.repo,
        tool_name: "CodeQL",
        state: "open",
        ref: this.config.ref,
        per_page: 100,
        page,
        headers: { "X-GitHub-Api-Version": "2026-03-10" },
      });
      const pageAlerts = pageResponse.data as AlertSummary[];
      alerts.push(...pageAlerts);
      if (pageAlerts.length < 100) break;
    }
    const openAlertNumbers = new Set(
      alerts
        .filter((alert) => !alert.most_recent_instance?.commit_sha || alert.most_recent_instance.commit_sha === this.config.sha)
        .map((alert) => alert.number),
    );

    const runs: SarifLog["runs"] = [];
    for (const analysis of latestByCategory.values()) {
      const response = await this.octokit.request(
        "GET /repos/{owner}/{repo}/code-scanning/analyses/{analysis_id}",
        {
          owner: this.config.owner,
          repo: this.config.repo,
          analysis_id: analysis.id,
          headers: {
            accept: "application/sarif+json",
            "X-GitHub-Api-Version": "2026-03-10",
          },
        },
      );
      if (!isSarifLog(response.data)) throw new Error(`GitHub returned invalid SARIF for CodeQL analysis ${analysis.id}`);
      for (const run of response.data.runs) {
        runs.push({
          ...run,
          results: (run.results || []).filter((result) => {
            const number = alertNumber(result);
            return number !== null && openAlertNumbers.has(number);
          }),
        });
      }
    }

    return {
      version: "2.1.0",
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      runs,
    };
  }

  async uploadSarif(sarif: SarifLog): Promise<string> {
    const encoded = gzipSync(Buffer.from(JSON.stringify(sarif), "utf8")).toString("base64");
    const response = await this.octokit.request("POST /repos/{owner}/{repo}/code-scanning/sarifs", {
      owner: this.config.owner,
      repo: this.config.repo,
      commit_sha: this.config.sha,
      ref: this.config.ref,
      sarif: encoded,
      tool_name: "Codex Security Consolidated",
      validate: true,
      started_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
      headers: { "X-GitHub-Api-Version": "2026-03-10" },
    });
    const id = (response.data as { id?: string }).id;
    if (!id) throw new Error("GitHub accepted the SARIF request without returning an upload id");
    return id;
  }

  async waitForUpload(uploadId: string): Promise<void> {
    for (let attempt = 1; attempt <= 30; attempt += 1) {
      const response = await this.octokit.request(
        "GET /repos/{owner}/{repo}/code-scanning/sarifs/{sarif_id}",
        {
          owner: this.config.owner,
          repo: this.config.repo,
          sarif_id: uploadId,
          headers: { "X-GitHub-Api-Version": "2026-03-10" },
        },
      );
      const status = (response.data as { processing_status?: string; errors?: string[] }).processing_status;
      if (status === "complete") return;
      if (status === "failed") {
        const errors = (response.data as { errors?: string[] }).errors?.join("; ") || "unknown GitHub processing error";
        throw new Error(`GitHub rejected SARIF upload ${uploadId}: ${errors}`);
      }
      await new Promise((resolve) => setTimeout(resolve, 2_000));
    }
    throw new Error(`Timed out waiting for GitHub to process SARIF upload ${uploadId}`);
  }
}
