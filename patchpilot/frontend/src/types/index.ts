export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type TriageStatus = 'open' | 'confirmed' | 'false_positive' | 'mitigated';

export interface ScanStage {
  id: string;
  label: string;
  description: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  durationMs?: number;
}

export interface Citation {
  source: string;
  sourceType: 'CWE' | 'NVD' | 'OWASP' | 'PEP';
  quote: string;
  similarityScore: number;
  verified: boolean;
}

export interface Explanation {
  summary: string;
  vulnerabilityMechanism: string;
  exploitabilityContext: string;
  remediationAdvice: string;
  citations: Citation[];
}

export interface LineAttribution {
  lineNumber: number;
  lineContent: string;
  attributionScore: number; // 0.0 to 1.0 (from Integrated Gradients)
  isPeak: boolean;
}

export interface Finding {
  id: string;
  scanId: string;
  cweId: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: number; // Calibrated probability 0.0 - 1.0
  analyzer: 'bandit' | 'semgrep' | 'unixcoder' | 'ensemble';
  lineNumber: number;
  lineEndNumber?: number;
  codeSnippet: string;
  triageStatus: TriageStatus;
  attributions: LineAttribution[];
  explanation?: Explanation;
  suggestedPatch?: PatchResult;
}

export interface VerificationGate {
  gate: string;
  passed: boolean;
  message: string;
}

export interface PatchResult {
  id: string;
  findingId: string;
  diff: string;
  patchedCode: string;
  attemptNumber: number;
  verified: boolean;
  gates: VerificationGate[];
  mlScoreBefore: number;
  mlScoreAfter: number;
  createdAt: string;
}

export interface Scan {
  id: string;
  filename: string;
  sourceCode: string;
  status: 'queued' | 'scanning' | 'completed' | 'failed';
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  avgRiskScore: number;
  createdAt: string;
  findings: Finding[];
}

export interface SystemStats {
  totalScans: number;
  vulnerabilitiesDetected: number;
  patchesVerified: number;
  remediationRatePercent: number;
  avgScanDurationSec: number;
  llmBudgetUsedUsd: number;
  llmBudgetCapUsd: number;
}
