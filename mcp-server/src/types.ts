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

// A completed scan's full report. Returned both by a fresh scan (POST
// /api/mcp/scan) and by retrieval (GET /api/mcp/scans/:id) — the backend emits
// the same shape for both, so one formatter renders either. The fields that
// differ are optional: creditsRemaining is present only on a fresh (paid) scan;
// createdAt/completedAt are present only on a retrieved historical report.
export interface ScanReport {
  success: true;
  targetUrl: string;
  postureScore: number;
  vulnerabilityLevel: Severity;
  analysisSummary: string;
  executiveBreakdown: ExecutiveBreakdown;
  securityFindings: Finding[];
  evidence?: unknown;
  creditsRemaining?: number;
  createdAt?: string;
  completedAt?: string;
}

// A fresh scan always reports the post-charge credit balance.
export interface ScanSuccess extends ScanReport {
  creditsRemaining: number;
}

// One row in the compact scan-history list (GET /api/mcp/scans) — no finding
// bodies, just enough to identify a scan and fetch it in full by id.
export interface ScanListItem {
  id: string;
  url: string;
  status: string;
  score: number | null;
  severity: Severity | null;
  createdAt: string;
  completedAt: string | null;
}

export interface ScanListSuccess {
  success: true;
  scans: ScanListItem[];
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
