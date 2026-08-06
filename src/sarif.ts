import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { CandidateFinding, SarifLog, SarifResult, SarifRule } from "./types.js";

const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";

export async function readSarif(filePath: string): Promise<SarifLog> {
  const parsed: unknown = JSON.parse(await readFile(filePath, "utf8"));
  if (
    !parsed ||
    typeof parsed !== "object" ||
    (parsed as { version?: unknown }).version !== "2.1.0" ||
    !Array.isArray((parsed as { runs?: unknown }).runs)
  ) {
    throw new Error(`${filePath} is not a SARIF 2.1.0 log`);
  }
  return parsed as SarifLog;
}

export function countResults(sarif: SarifLog): number {
  return sarif.runs.reduce((count, run) => count + (run.results?.length || 0), 0);
}

function ruleForResult(run: SarifLog["runs"][number], result: SarifResult): SarifRule {
  const indexed = result.ruleIndex === undefined ? undefined : run.tool.driver.rules?.[result.ruleIndex];
  const id = result.ruleId || indexed?.id;
  if (!id) throw new Error("A validated CodeQL SARIF result is missing ruleId and ruleIndex");
  return indexed ? { ...indexed, id } : { id, shortDescription: { text: id } };
}

function slug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 48) || "finding";
}

function codexRuleId(finding: CandidateFinding): string {
  const cwe = slug(finding.cwes[0] || "unknown");
  return `codex/dataflow/${cwe}/${slug(finding.title)}`;
}

function codexFingerprint(finding: CandidateFinding): string {
  const source = finding.flowSteps[0]!;
  const sink = finding.flowSteps.at(-1)!;
  return createHash("sha256")
    .update([finding.cwes.slice().sort().join(","), source.path, source.line, sink.path, sink.line].join("\0"))
    .digest("hex");
}

function codexRule(finding: CandidateFinding): SarifRule {
  const id = codexRuleId(finding);
  const markdown = `### Vulnerability\n\n${finding.vulnerability}\n\n### Risk\n\n${finding.risk}\n\n### Generic remediation\n\n${finding.remediation}`;
  return {
    id,
    name: slug(finding.title).replaceAll("-", "_"),
    shortDescription: { text: finding.title },
    fullDescription: { text: finding.vulnerability },
    help: { text: `${finding.vulnerability}\n\nRisk: ${finding.risk}\n\nRemediation: ${finding.remediation}`, markdown },
    properties: {
      tags: ["security", ...finding.cwes.map((cwe) => `external/cwe/${cwe.toLowerCase()}`)],
      precision: "high",
      "security-severity": finding.severity === "error" ? "9.0" : finding.severity === "warning" ? "6.0" : "3.0",
      source: "Codex",
    },
  };
}

function codexResult(finding: CandidateFinding): SarifResult {
  const ruleId = codexRuleId(finding);
  const primary = finding.primaryLocation;
  return {
    ruleId,
    level: finding.severity,
    message: {
      text: `${finding.vulnerability}\n\nRisk: ${finding.risk}\n\nGeneric remediation: ${finding.remediation}`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: primary.path },
          region: { startLine: primary.line },
        },
        message: { text: finding.title },
      },
    ],
    codeFlows: [
      {
        message: { text: `Uncovered dataflow for ${finding.title}` },
        threadFlows: [
          {
            locations: finding.flowSteps.map((step, index) => ({
              location: {
                physicalLocation: {
                  artifactLocation: { uri: step.path },
                  region: { startLine: step.line },
                },
                message: { text: `${step.role}: ${step.message}` },
              },
              importance: index === 0 || index === finding.flowSteps.length - 1 ? "essential" : "important",
            })),
          },
        ],
      },
    ],
    partialFingerprints: { "codexSecurity/dataflow/v1": codexFingerprint(finding) },
    properties: {
      source: "Codex",
      confidence: finding.confidence,
      cwes: finding.cwes,
      candidateId: finding.candidateId,
    },
  };
}

export function buildConsolidatedSarif(validatedCodeql: SarifLog, findings: CandidateFinding[]): SarifLog {
  const rules = new Map<string, SarifRule>();
  const results: SarifResult[] = [];

  for (const run of validatedCodeql.runs) {
    for (const result of run.results || []) {
      const rule = ruleForResult(run, result);
      if (!rules.has(rule.id)) rules.set(rule.id, { ...rule, properties: { ...rule.properties, source: "CodeQL" } });
      const { ruleIndex: _discarded, ...copy } = result;
      results.push({
        ...copy,
        ruleId: rule.id,
        properties: { ...result.properties, source: "CodeQL", validated: true },
      });
    }
  }

  for (const finding of findings) {
    const rule = codexRule(finding);
    if (!rules.has(rule.id)) rules.set(rule.id, rule);
    results.push(codexResult(finding));
  }

  const finalRules = [...rules.values()];
  const ruleIndexes = new Map(finalRules.map((rule, index) => [rule.id, index]));
  const indexedResults = results.map((result) => {
    const ruleIndex = ruleIndexes.get(result.ruleId!);
    if (ruleIndex === undefined) throw new Error(`No rule index exists for ${result.ruleId}`);
    return { ...result, ruleIndex };
  });

  return {
    version: "2.1.0",
    $schema: SARIF_SCHEMA,
    runs: [
      {
        tool: {
          driver: {
            name: "Codex Security Consolidated",
            version: "0.1.0",
            semanticVersion: "0.1.0",
            informationUri: "https://github.com/openai/codex",
            rules: finalRules,
          },
        },
        automationDetails: { id: "codex-security/weekly" },
        results: indexedResults,
        invocations: [{ executionSuccessful: true }],
        properties: {
          codeqlValidatedFindingCount: countResults(validatedCodeql),
          codexFindingCount: findings.length,
        },
      },
    ],
  };
}
