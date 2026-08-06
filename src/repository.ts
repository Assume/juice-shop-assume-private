import { execFile } from "node:child_process";
import { lstatSync, readFileSync } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";
import type { CandidateFinding, FlowStep } from "./types.js";

const execFileAsync = promisify(execFile);

export async function trackedFiles(workspace: string): Promise<Set<string>> {
  const { stdout } = await execFileAsync("git", ["ls-files", "-z", "--cached"], {
    cwd: workspace,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  return new Set(stdout.split("\0").filter(Boolean).map((entry) => entry.replaceAll("\\", "/")));
}

export function normalizeRepoPath(candidate: string): string | null {
  if (!candidate || candidate.includes("\0")) return null;
  const slashed = candidate.replaceAll("\\", "/");
  const normalized = path.posix.normalize(slashed);
  if (
    normalized === "." ||
    normalized === ".." ||
    normalized.startsWith("../") ||
    path.posix.isAbsolute(normalized) ||
    /^[a-zA-Z]:\//.test(normalized)
  ) {
    return null;
  }
  return normalized;
}

function validateStep(step: FlowStep, workspace: string, files: Set<string>): string | null {
  const normalized = normalizeRepoPath(step.path);
  if (!normalized || !files.has(normalized)) return `untracked or unsafe path: ${step.path}`;
  if (!Number.isInteger(step.line) || step.line < 1) return `invalid line for ${step.path}`;

  const absolute = path.join(workspace, ...normalized.split("/"));
  const stat = lstatSync(absolute);
  if (!stat.isFile() || stat.isSymbolicLink()) return `path is not a regular repository file: ${step.path}`;
  const lineCount = readFileSync(absolute, "utf8").split(/\r?\n/).length;
  if (step.line > lineCount) return `line ${step.line} is outside ${step.path} (${lineCount} lines)`;
  if (!step.message.trim()) return `missing dataflow explanation for ${step.path}:${step.line}`;
  return null;
}

export function validateFinding(
  finding: CandidateFinding,
  workspace: string,
  files: Set<string>,
): { ok: true; finding: CandidateFinding } | { ok: false; reason: string } {
  if (!finding.title.trim()) return { ok: false, reason: "missing title" };
  if (finding.cwes.length === 0) return { ok: false, reason: "at least one CWE is required" };
  if (finding.cwes.some((cwe) => !/^CWE-\d+$/i.test(cwe))) {
    return { ok: false, reason: "CWEs must use the CWE-<number> format" };
  }
  if (finding.flowSteps.length < 2) return { ok: false, reason: "a dataflow needs at least a source and sink" };
  if (finding.flowSteps[0]?.role !== "source") return { ok: false, reason: "first dataflow step must be the source" };
  if (finding.flowSteps.at(-1)?.role !== "sink") return { ok: false, reason: "last dataflow step must be the sink" };

  const normalizedSteps: FlowStep[] = [];
  for (const step of finding.flowSteps) {
    const failure = validateStep(step, workspace, files);
    if (failure) return { ok: false, reason: failure };
    normalizedSteps.push({ ...step, path: normalizeRepoPath(step.path)! });
  }

  const primaryPath = normalizeRepoPath(finding.primaryLocation.path);
  if (!primaryPath) return { ok: false, reason: "invalid primary location path" };
  const primaryMatchesFlow = normalizedSteps.some(
    (step) => step.path === primaryPath && step.line === finding.primaryLocation.line,
  );
  if (!primaryMatchesFlow) return { ok: false, reason: "primary location must match a dataflow step" };

  return {
    ok: true,
    finding: {
      ...finding,
      cwes: finding.cwes.map((cwe) => cwe.toUpperCase()),
      primaryLocation: { path: primaryPath, line: finding.primaryLocation.line },
      flowSteps: normalizedSteps,
    },
  };
}

export function deduplicateFindings(findings: CandidateFinding[]): CandidateFinding[] {
  const seen = new Set<string>();
  const result: CandidateFinding[] = [];
  for (const finding of findings) {
    const source = finding.flowSteps[0]!;
    const sink = finding.flowSteps.at(-1)!;
    const key = [source.path, source.line, sink.path, sink.line, finding.cwes.slice().sort().join(",")].join(":");
    if (!seen.has(key)) {
      seen.add(key);
      result.push(finding);
    }
  }
  return result;
}
