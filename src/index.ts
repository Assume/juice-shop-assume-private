import { execFile } from "node:child_process";
import { appendFile, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import {
  applyVerifications,
  assignCandidateIds,
  discoverDataflows,
  verifyDataflows,
} from "./codex.js";
import { loadConfig } from "./config.js";
import { GitHubCodeScanning } from "./github.js";
import { deduplicateFindings, trackedFiles, validateFinding } from "./repository.js";
import { buildConsolidatedSarif, countResults, readSarif } from "./sarif.js";
import type { AuditReport, SarifLog, VerificationOutput } from "./types.js";

const execFileAsync = promisify(execFile);

function isInside(parent: string, candidate: string): boolean {
  const relative = path.relative(parent, candidate);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

function resolveInside(workspace: string, candidate: string, label: string): string {
  const resolved = path.resolve(workspace, candidate);
  if (!isInside(workspace, resolved)) throw new Error(`${label} must resolve inside GITHUB_WORKSPACE`);
  return resolved;
}

async function assertCheckout(workspace: string, expectedSha: string): Promise<void> {
  const { stdout } = await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: workspace, encoding: "utf8" });
  const actual = stdout.trim();
  if (actual !== expectedSha) {
    throw new Error(`Checked-out commit ${actual} does not match GITHUB_SHA ${expectedSha}`);
  }
}

async function writeJson(filePath: string, value: unknown): Promise<void> {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}

async function setOutput(name: string, value: string | number): Promise<void> {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (outputFile) await appendFile(outputFile, `${name}=${String(value)}\n`, "utf8");
  else console.log(`${name}=${String(value)}`);
}

async function writeSummary(report: AuditReport, sarifPath: string, reportPath: string): Promise<void> {
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryFile) return;
  const upload = report.uploadId ? `Uploaded successfully (id: \`${report.uploadId}\`)` : "Dry run; not uploaded";
  const content = `## Codex security consolidation\n\n| Result | Count |\n| --- | ---: |\n| Validated CodeQL findings | ${report.codeqlFindingCount} |\n| Codex candidates | ${report.discoveredCandidateCount} |\n| Independently validated Codex findings | ${report.codexFindingCount} |\n| Rejected/uncertain candidates | ${report.rejectedCandidateCount} |\n\n${upload}.\n\n- SARIF: \`${path.relative(process.cwd(), sarifPath)}\`\n- Audit report: \`${path.relative(process.cwd(), reportPath)}\`\n- Coverage: ${report.coverage.summary}\n`;
  await appendFile(summaryFile, content, "utf8");
}

async function main(): Promise<void> {
  const config = loadConfig();
  await assertCheckout(config.workspace, config.sha);

  const outputDirectory = resolveInside(config.workspace, config.outputDirectory, "output-directory");
  await mkdir(outputDirectory, { recursive: true, mode: 0o700 });

  const github = new GitHubCodeScanning(config);
  let validatedCodeql: SarifLog;
  if (config.validatedCodeqlSarif) {
    validatedCodeql = await readSarif(
      resolveInside(config.workspace, config.validatedCodeqlSarif, "validated-codeql-sarif"),
    );
  } else {
    validatedCodeql = await github.downloadOpenCodeqlSarif();
  }

  const contextSarifPath = path.join(outputDirectory, "validated-codeql-context.sarif");
  const candidatePath = path.join(outputDirectory, "codex-candidates.json");
  const verificationPath = path.join(outputDirectory, "codex-verifications.json");
  const sarifPath = path.join(outputDirectory, "consolidated.sarif");
  const reportPath = path.join(outputDirectory, "audit-report.json");
  await writeJson(contextSarifPath, validatedCodeql);

  console.log("Running read-only Codex discovery against uncovered repository dataflows...");
  const discovery = await discoverDataflows(config, {
    validatedSarifPath: path.relative(config.workspace, contextSarifPath),
    candidatePath: path.relative(config.workspace, candidatePath),
  });
  const candidates = assignCandidateIds(discovery).slice(0, config.maximumFindings);
  await writeJson(candidatePath, { findings: candidates, coverage: discovery.coverage });

  let verification: VerificationOutput = { verifications: [] };
  if (candidates.length > 0) {
    console.log(`Independently validating ${candidates.length} Codex candidate(s)...`);
    verification = await verifyDataflows(config, {
      validatedSarifPath: path.relative(config.workspace, contextSarifPath),
      candidatePath: path.relative(config.workspace, candidatePath),
    });
  }
  await writeJson(verificationPath, verification);

  const verified = applyVerifications(candidates, verification, config.minimumConfidence);
  const files = await trackedFiles(config.workspace);
  const deterministicRejections: Array<{ candidateId: string; reason: string }> = [];
  const grounded = verified.accepted.flatMap((finding) => {
    const result = validateFinding(finding, config.workspace, files);
    if (!result.ok) {
      deterministicRejections.push({ candidateId: finding.candidateId, reason: result.reason });
      return [];
    }
    return [result.finding];
  });
  const accepted = deduplicateFindings(grounded).slice(0, config.maximumFindings);
  const duplicateCount = grounded.length - accepted.length;
  if (duplicateCount > 0) {
    deterministicRejections.push({ candidateId: "deduplication", reason: `${duplicateCount} duplicate flow(s) removed` });
  }

  const consolidated = buildConsolidatedSarif(validatedCodeql, accepted);
  await writeJson(sarifPath, consolidated);

  let uploadId: string | null = null;
  if (config.upload) {
    console.log("Uploading validated consolidated SARIF to GitHub Code Scanning...");
    uploadId = await github.uploadSarif(consolidated);
    await github.waitForUpload(uploadId);
  }

  const rejections = [...verified.rejected, ...deterministicRejections];
  const report: AuditReport = {
    repository: config.repository,
    ref: config.ref,
    sha: config.sha,
    generatedAt: new Date().toISOString(),
    model: config.model,
    codeqlFindingCount: countResults(validatedCodeql),
    discoveredCandidateCount: candidates.length,
    codexFindingCount: accepted.length,
    rejectedCandidateCount: rejections.length,
    coverage: discovery.coverage,
    findings: accepted,
    rejections,
    uploadId,
  };
  await writeJson(reportPath, report);

  await Promise.all([
    setOutput("sarif-path", sarifPath),
    setOutput("report-path", reportPath),
    setOutput("upload-id", uploadId || ""),
    setOutput("codeql-findings", report.codeqlFindingCount),
    setOutput("codex-findings", report.codexFindingCount),
  ]);
  await writeSummary(report, sarifPath, reportPath);
  console.log(
    `Complete: ${report.codeqlFindingCount} validated CodeQL and ${report.codexFindingCount} validated Codex finding(s).`,
  );
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack || error.message : String(error);
  console.error(`Codex Security Consolidator failed: ${message}`);
  process.exitCode = 1;
});
