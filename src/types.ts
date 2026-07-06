export type ScanStatus = 'queued' | 'scanning' | 'analyzing' | 'complete' | 'failed';
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface User {
  id: string;
  email: string;
  credits: number;
  notifyWebhook?: string; // optional Slack-compatible alert webhook
  createdAt: string;
}

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  confidence?: 'low' | 'medium' | 'high';
  fix: string;
  category: string;
  owasp?: string; // mapped OWASP Top 10 2021 category, e.g. "A03:2021 – Injection"
  isFalsePositive?: boolean;
  suppressionReason?: string;
  suppressedAt?: string;
  endpoint?: string;
  rawRequest?: string;
  rawResponse?: string;
  impact?: string; // plain-English consequence if this is exploited
  // Ready-to-paste instructions for an AI coding agent (Cursor, Claude Code,
  // Windsurf, etc.) to locate and fix this specific finding in the user's own
  // codebase.
  agentPrompt?: string;
}

export interface SuppressionRule {
  id: string;
  userId: string;
  targetUrl: string;
  findingTitle: string;
  reason: string;
  createdAt: string;
}

export interface Scan {
  id: string;
  userId: string;
  url: string;
  authHeader?: string;
  status: ScanStatus;
  score?: number; // 0 - 100
  severity?: Severity;
  findings?: Finding[];
  aiSummary?: string;
  // The model's chain-of-thought from DeepSeek's thinking mode, when
  // available — surfaced in the UI as an optional "how the AI assessed this"
  // trace. Undefined when DeepSeek isn't configured or thinking mode wasn't used.
  aiReasoning?: string;
  // Real-time progress narration (deepseek-v4-flash), describing what the
  // scanning and analysis phases actually found. Appended to as the scan
  // progresses; read by the ScanProgress UI instead of scripted filler text.
  narrationLog?: string[];
  executiveBreakdown?: ExecutiveBreakdown;
  evidence?: ScanEvidence; // real diagnostic evidence behind the findings
  error?: string;
  createdAt: string;
  completedAt?: string;
}

export interface CreditTransaction {
  id: string;
  userId: string;
  amount: number; // e.g. +5, -1
  type: 'purchase' | 'scan_debit';
  stripeSessionId?: string;
  createdAt: string;
}

export interface MonitoredTarget {
  id: string;
  userId: string;
  url: string;
  frequencyDays: number;
  scheduleString?: string;
  lastScannedAt?: string;
  nextScanAt?: string;
  createdAt: string;
}

export interface ApiKey {
  id: string;
  userId: string;
  // The full secret is never persisted or re-displayed — only a safe-to-show
  // preview (e.g. "sl_live_ab12…9c01"). The raw key is returned exactly once,
  // in the response to the generate-key call.
  keyPreview: string;
  credits: number;
  active: boolean;
  createdAt: string;
}

// A compact, display-oriented slice of the raw scan diagnostics — the real
// evidence behind the findings (resolved IP, nameserver, live subdomains,
// per-path probe results, detected libraries, crawl coverage, header state).
// Persisted on the scan and rendered in the report so the "Network & Attack
// Surface" and raw-log sections show the ACTUAL target data instead of
// placeholder values.
export interface ScanEvidence {
  scannedAt: string;
  responseStatus: number;
  protocol: string; // "HTTPS" | "HTTP"
  resolvedIp?: string;
  nameserver?: string;
  serverHeader?: string; // value of the Server response header, if disclosed
  presentSecurityHeaders: string[]; // which of the tracked headers ARE set
  missingSecurityHeaders: string[]; // which are absent
  liveSubdomains: string[]; // subdomain hostnames that resolved live
  subdomainsChecked: number; // how many candidate subdomains were probed
  probedPaths: Array<{ path: string; status: number; exposed: boolean }>;
  detectedLibraries: Array<{ name: string; version: string; vulnerable: boolean }>;
  crawl?: { pagesVisited: number; endpointsDiscovered: number; paramsTested: number; sampleEndpoints: string[] };
  activeProbesRun: boolean; // false when gated off for an unverified domain
}

export interface ExecutiveRiskArea {
  area: string; // e.g. "Injection & Input Validation"
  detail: string; // 1-2 sentences on this theme's specific findings/risk
}

// A detailed, multi-part breakdown of the scan — distinct from the single
// aiSummary paragraph (which stays a short headline, used everywhere that
// already reads it: dashboard toasts, PDF export, Slack alerts). Rendered by
// ReportViewer as its own structured section. Always populated — with a
// deterministic local fallback when DeepSeek isn't configured — same pattern
// as Finding.impact/agentPrompt.
export interface ExecutiveBreakdown {
  overview: string;
  riskAreas: ExecutiveRiskArea[];
  businessImpact: string;
  priorityActions: string[]; // ranked, most urgent first
}

export interface DomainVerification {
  id: string;
  userId: string;
  domain: string;
  token: string;
  verified: boolean;
  createdAt: string;
  verifiedAt?: string;
}
