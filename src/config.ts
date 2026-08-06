import path from "node:path";

export type ReasoningEffort = "low" | "medium" | "high" | "xhigh";

export type Config = {
  githubToken: string;
  openaiApiKey: string;
  codexPath: string;
  repository: string;
  owner: string;
  repo: string;
  sha: string;
  ref: string;
  workspace: string;
  validatedCodeqlSarif?: string;
  model: string;
  reasoningEffort: ReasoningEffort;
  minimumConfidence: number;
  maximumFindings: number;
  outputDirectory: string;
  upload: boolean;
};

function value(env: NodeJS.ProcessEnv, input: string, fallbackName?: string): string | undefined {
  return env[`INPUT_${input.toUpperCase().replaceAll("-", "_")}`] || (fallbackName ? env[fallbackName] : undefined);
}

function required(name: string, candidate: string | undefined): string {
  const result = candidate?.trim();
  if (!result) throw new Error(`Missing required configuration: ${name}`);
  return result;
}

function parseBoolean(name: string, candidate: string | undefined, fallback: boolean): boolean {
  if (candidate === undefined || candidate.trim() === "") return fallback;
  if (candidate.toLowerCase() === "true") return true;
  if (candidate.toLowerCase() === "false") return false;
  throw new Error(`${name} must be true or false`);
}

function safeRelativeDirectory(candidate: string): string {
  const normalized = path.posix.normalize(candidate.replaceAll("\\", "/"));
  if (path.posix.isAbsolute(normalized) || normalized === ".." || normalized.startsWith("../")) {
    throw new Error("output-directory must stay inside the checked-out repository");
  }
  return normalized;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const repository = required("GITHUB_REPOSITORY", env.GITHUB_REPOSITORY);
  const [owner, repo, extra] = repository.split("/");
  if (!owner || !repo || extra) throw new Error("GITHUB_REPOSITORY must have the form owner/repo");

  const confidence = Number(value(env, "minimum-confidence") || "0.80");
  if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
    throw new Error("minimum-confidence must be between 0 and 1");
  }

  const maximumFindings = Number(value(env, "maximum-findings") || "100");
  if (!Number.isInteger(maximumFindings) || maximumFindings < 1 || maximumFindings > 500) {
    throw new Error("maximum-findings must be an integer between 1 and 500");
  }

  const reasoningEffort = (value(env, "reasoning-effort") || "xhigh") as ReasoningEffort;
  if (!["low", "medium", "high", "xhigh"].includes(reasoningEffort)) {
    throw new Error("reasoning-effort must be low, medium, high, or xhigh");
  }

  const ref = required("GITHUB_REF", env.GITHUB_REF);
  if (!ref.startsWith("refs/")) throw new Error("GITHUB_REF must be a fully qualified Git ref");

  return {
    githubToken: required("github-token", value(env, "github-token", "GITHUB_TOKEN")),
    openaiApiKey: required("openai-api-key", value(env, "openai-api-key", "OPENAI_API_KEY")),
    codexPath: value(env, "codex-path")?.trim() || "codex",
    repository,
    owner,
    repo,
    sha: required("GITHUB_SHA", env.GITHUB_SHA),
    ref,
    workspace: path.resolve(required("GITHUB_WORKSPACE", env.GITHUB_WORKSPACE)),
    ...(value(env, "validated-codeql-sarif")?.trim()
      ? { validatedCodeqlSarif: value(env, "validated-codeql-sarif")!.trim() }
      : {}),
    model: value(env, "model")?.trim() || "gpt-5.6-sol",
    reasoningEffort,
    minimumConfidence: confidence,
    maximumFindings,
    outputDirectory: safeRelativeDirectory(value(env, "output-directory")?.trim() || "security-artifacts"),
    upload: parseBoolean("upload", value(env, "upload"), true),
  };
}
