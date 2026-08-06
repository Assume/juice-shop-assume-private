export type SarifRegion = {
  startLine?: number;
  startColumn?: number;
  endLine?: number;
  endColumn?: number;
};

export type SarifLocation = {
  physicalLocation?: {
    artifactLocation?: { uri?: string; uriBaseId?: string };
    region?: SarifRegion;
  };
  message?: { text?: string; markdown?: string };
};

export type SarifRule = {
  id: string;
  name?: string;
  shortDescription?: { text: string };
  fullDescription?: { text: string };
  help?: { text?: string; markdown?: string };
  properties?: Record<string, unknown>;
};

export type SarifResult = {
  ruleId?: string;
  ruleIndex?: number;
  level?: "none" | "note" | "warning" | "error";
  message: { text?: string; markdown?: string };
  locations?: SarifLocation[];
  codeFlows?: Array<{
    message?: { text?: string };
    threadFlows: Array<{
      locations: Array<{
        location: SarifLocation;
        importance?: "unimportant" | "important" | "essential";
      }>;
    }>;
  }>;
  partialFingerprints?: Record<string, string>;
  properties?: Record<string, unknown>;
  [key: string]: unknown;
};

export type SarifRun = {
  tool: {
    driver: {
      name: string;
      version?: string;
      semanticVersion?: string;
      informationUri?: string;
      rules?: SarifRule[];
    };
  };
  automationDetails?: { id?: string };
  results?: SarifResult[];
  [key: string]: unknown;
};

export type SarifLog = {
  version: "2.1.0";
  $schema?: string;
  runs: SarifRun[];
};

export type FlowStep = {
  path: string;
  line: number;
  message: string;
  role: "source" | "propagation" | "sanitizer-gap" | "sink";
};

export type CandidateFinding = {
  candidateId: string;
  title: string;
  severity: "note" | "warning" | "error";
  confidence: number;
  cwes: string[];
  vulnerability: string;
  risk: string;
  remediation: string;
  primaryLocation: { path: string; line: number };
  flowSteps: FlowStep[];
};

export type DiscoveryOutput = {
  findings: Omit<CandidateFinding, "candidateId">[];
  coverage: {
    summary: string;
    examinedAreas: string[];
    excludedAreas: string[];
    limitations: string[];
  };
};

export type Verification = {
  candidateId: string;
  verdict: "confirmed" | "rejected" | "uncertain";
  confidence: number;
  rationale: string;
  correctedFlowSteps: FlowStep[];
  correctedPrimaryLocation: { path: string; line: number };
};

export type VerificationOutput = { verifications: Verification[] };

export type AuditReport = {
  repository: string;
  ref: string;
  sha: string;
  generatedAt: string;
  model: string;
  codeqlFindingCount: number;
  discoveredCandidateCount: number;
  codexFindingCount: number;
  rejectedCandidateCount: number;
  coverage: DiscoveryOutput["coverage"];
  findings: CandidateFinding[];
  rejections: Array<{ candidateId: string; reason: string }>;
  uploadId: string | null;
};
