export type ScanStatus = 'queued' | 'scanning' | 'analyzing' | 'complete' | 'failed' | 'canceled';
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface User {
  id: string;
  email: string;
  credits: number;
  notifyWebhook?: string; // optional Slack-compatible alert webhook
  createdAt: string;
}

// A single request/response pair captured verbatim during active probing — the
// raw material of a PROVEN finding's receipt. Bodies are truncated with an
// explicit "[…truncated N bytes]" marker (never silently), and credentials are
// redacted while the payload that constitutes the proof is preserved.
export interface RawExchange {
  request: string;   // raw HTTP request line + headers + body (secrets redacted)
  response: string;  // status line + headers + body (explicitly truncated)
  identity?: string; // which test identity issued it, e.g. "tenant-A"
}

// The stored, replayable proof behind a PROVEN finding. Its presence — plus a
// `signal.quote` that is a literal substring of `attack.response` — is what earns
// a finding the top "PROVEN" tier (see server/scoring.ts:isProven). Without a
// valid bundle a finding still ships, just in the DETECTED tier.
export interface ExploitEvidence {
  method: 'reflection' | 'error-signature' | 'oracle' | 'differential' | 'introspection' | 'out-of-band';
  attack: RawExchange;      // the request that demonstrated the flaw
  baseline?: RawExchange;   // authorized/benign control request, when the class uses one
  control?: RawExchange;    // negative control (e.g. unauthenticated → denied)
  // The exact bytes that prove the finding, quoted verbatim from `attack.response`
  // so the UI can highlight them. `offsetInResponse` indexes into the stored
  // response string; `why` is a one-line explanation of what the quote proves.
  signal: { quote: string; offsetInResponse: number; why: string };
  // One plain-English sentence a non-technical builder can read and believe.
  demonstration: string;
  reproduction: string;     // copy-pasteable curl to replay the attack exchange
  capturedAt: string;
  // Ownership proof this active action was gated behind, when threaded through.
  ownership?: { verificationId?: string; method?: 'dns' | 'file' };
}

// A recorded out-of-band callback: the scanned target reached back to our
// collaborator endpoint after we injected its unique URL into a payload. Its
// existence is the proof of a BLIND vulnerability (SSRF/RCE/XXE) where nothing
// is reflected inline — see server/oob.ts and the 'out-of-band' evidence method.
export interface OobEvent {
  id: string;
  token: string;       // the unique per-probe token embedded in the callback URL
  method: string;      // HTTP method the target used to reach us (GET/POST/…)
  sourceIp: string;    // remote address the callback came from
  path: string;        // full path the target requested on the collaborator
  userAgent?: string;  // User-Agent the target sent, when present
  receivedAt: string;
}

// One of the two owned test identities required to PROVE a cross-tenant BOLA/IDOR
// (see docs/confirmed-evidence-spec.md §3.1a). Authorization is relational: you
// cannot prove an object should have been private from a single request, so a
// Confirmed/PROVEN BOLA requires reading identity B's object as identity A.
export interface BolaIdentity {
  label: string;       // human tag, e.g. "tenant-A"
  authHeader: string;  // this identity's credential (Authorization/Cookie/…)
  ownResource: string; // a path/URL to an object this identity owns, e.g. "/api/v1/orders/1001"
  ownMarker?: string;  // a value known to be unique to this identity's data (e.g. its email)
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
  // Stored, replayable exploit receipt. When present and valid this promotes the
  // finding to the PROVEN tier and carries the raw request/response exchange(s).
  evidence?: ExploitEvidence;
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
  // Structured time-of-day the schedule fires at, in UTC. `scanWeekday` (0=Sun)
  // applies to weekly cadences. When these are null the target falls back to a
  // fixed now+frequencyDays interval (legacy rows).
  scanHour?: number | null;
  scanMinute?: number | null;
  scanWeekday?: number | null;
  lastScannedAt?: string;
  nextScanAt?: string;
  createdAt: string;
  // Set when the most recent tick couldn't launch a scan for this target
  // (invalid/unsafe URL, or insufficient credits); cleared the next time a
  // scan is successfully launched. Surfaced in the dashboard so a monitor
  // that's silently never scanning anything doesn't just show "Active".
  lastError?: string;
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
  screenshot?: TargetScreenshot; // headless-browser capture of the target, when enabled
}

// A visual capture of the scanned target's landing page, taken by a headless
// browser (see server/render.ts captureScreenshot). Stored inline as a data:
// URI so the report is self-contained. Only present when target screenshotting
// is enabled (ENABLE_TARGET_SCREENSHOT) and the capture succeeded.
export interface TargetScreenshot {
  dataUri: string;   // e.g. "data:image/jpeg;base64,…"
  capturedAt: string;
  width: number;
  height: number;
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
  // How ownership was established: 'dns' or 'file' (cryptographic proof).
  method?: 'dns' | 'file';
}
