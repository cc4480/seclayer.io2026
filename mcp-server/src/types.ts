// Mirrors the subset of the Seclayer backend's response shapes this client
// actually consumes (see /home/user/seclayer.io2026/server/routes/mcp.ts and
// src/types.ts in the main app). Deliberately loose on fields this package
// never inspects (e.g. `evidence`) rather than importing the whole app's type
// tree into a small, independently-published CLI package.

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  confidence?: "low" | "medium" | "high";
  fix: string;
  category: string;
  owasp?: string;
  endpoint?: string;
  impact?: string;
  agentPrompt?: string;
  // Presence (not shape) is all this package cares about: it means the
  // finding carries a replayable exploit receipt, promoting it to "proven".
  evidence?: unknown;
}

export interface ExecutiveRiskArea {
  area: string;
  detail: string;
}

export interface ExecutiveBreakdown {
  overview: string;
  riskAreas: ExecutiveRiskArea[];
  businessImpact: string;
  priorityActions: string[];
}

export interface ScanSuccess {
  success: true;
  targetUrl: string;
  postureScore: number;
  vulnerabilityLevel: Severity;
  analysisSummary: string;
  executiveBreakdown: ExecutiveBreakdown;
  securityFindings: Finding[];
  evidence?: unknown;
  creditsRemaining: number;
}

// The backend is not fully consistent about its error envelope shape across
// routes/middleware (the route handler itself uses {error, details?,
// creditsRemaining?}; the shared rate-limit middleware uses {status,
// message}) — this type accepts either so the client can read whichever
// field is actually present rather than assuming one.
export interface ScanErrorBody {
  error?: string;
  message?: string;
  details?: string;
  creditsRemaining?: number;
}
