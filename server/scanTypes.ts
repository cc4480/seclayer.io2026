// Shared scan data contracts: the DiagnosticResult produced by runDiagnostics
// and the ScanOptions that configure it. Extracted so the probe/analysis modules
// can depend on the shapes without importing the scanner entry point.
import type { ChallengeVerdict } from "./challengePage.js";
import type { Finding, Severity, ExploitEvidence, BolaIdentity, LoginCredentials, ScanCoverage } from "../src/types.js";
import type { OobCollaborator } from "./oob.js";
import type { EmitFn } from "./scanEvents.js";

// A confirmed exploit result from an active red-team probe (see server/redTeam/).
// evidence, when present, is a captured receipt that promotes the finding to
// PROVEN (isProven checks the quoted signal is a literal substring of it).
export interface RedTeamFinding {
  testName: string;
  payload: string;
  severity: Severity;
  description: string;
  fix: string;
  evidence?: ExploitEvidence;
  // Almost every red-team probe proves its finding (a captured receipt or a
  // clean differential) and is reported at "high". A probe that can only make
  // an OBSERVATIONAL, non-provable claim — e.g. "no rate-limiting seen in N
  // attempts", where absence can't be positively proven — sets this to
  // "medium" so it is surfaced honestly as needs-verification, not PROVEN.
  // Omitted → treated as "high" (the existing behavior).
  confidence?: "low" | "medium" | "high";
}

export interface DiagnosticResult {
  url: string;
  scannedAt: string;
  responseStatus: number;
  sslSecure: boolean;
  headers: Record<string, string>;
  missingHeaders: string[];
  techLeaked: string[];
  probedPaths: Array<{
    path: string;
    status: number;
    exposed: boolean;
    body?: string;
    // Per-file finding metadata for probes that carry accurate severity/wording
    // (e.g. supply-chain lockfiles are a LOW dependency-tree disclosure, not the
    // generic critical/high the .env/.git default assigns). Absent → default map.
    meta?: { title: string; severity: Severity; description: string; fix: string };
  }>;
  cookieIssues: string[];
  // The literal Set-Cookie line each cookie issue was derived from, keyed by
  // the issue text, with the cookie VALUE redacted. Exists because these
  // findings are routinely disputed: a target can serve different cookie
  // attributes to a browser than to the scanner (google.com serves NID
  // WITHOUT Secure to a non-browser UA and WITH it to Chrome), so a user who
  // checks in DevTools sees the opposite of what we reported and concludes we
  // are wrong. Quoting what we were actually served makes a true finding
  // defensible instead of arguable.
  cookieEvidence: Record<string, string>;

  // High-fidelity AppSec dimensions
  sastFindings: Array<{
    file: string;
    issue: string;
    severity: Severity;
    confidence: "low" | "medium" | "high";
    type: string;
    fix: string;
    description: string;
    // A MASKED excerpt of the matched credential (see staticAnalysis.maskSecret):
    // leading token + last four, middle starred, true length stated. Identifies
    // which secret leaked without ever storing a usable one. Never the raw value.
    masked?: string;
  }>;
  scaLibraries: Array<{
    name: string;
    version: string;
    status: "vuln" | "safe";
    advisories: string[];
    severity: Severity;
    description: string;
    fix: string;
  }>;
  easmPerimeter: {
    subdomains: Array<{
      domain: string;
      status: "live" | "inactive";
      port: string;
    }>;
    ip: string;
    nameserver: string;
    protocol: string;
  };
  redTeamFindings?: RedTeamFinding[];
  crawl?: {
    pagesVisited: number;
    endpointsDiscovered: number;
    paramsTested: number;
    sampleEndpoints: string[];
  };
  templateFindings?: Finding[];
  apiSecFindings?: Array<{
    testName: string;
    severity: Severity;
    description: string;
    fix: string;
    endpoint: string;
    evidence?: ExploitEvidence; // stored exploit receipt (promotes to PROVEN)
    // A probe that can only make an INCONCLUSIVE claim — "could neither be
    // proven nor ruled out" — must say so here. Omitted → "high", so a probe
    // that stays silent is reported as CONFIRMED. See bola.ts's cross-tenant
    // branches, which read as "needs verification ... confirmed" until they
    // declared this.
    confidence?: "low" | "medium" | "high";
  }>;
  // True when active exploit probing (SQLi/XSS/cmd-injection/SSRF/GraphQL/BOLA
  // fuzzing) was skipped because the target's domain ownership isn't verified.
  activeProbesSkipped?: boolean;
  /**
   * Set when the target's edge answered with a challenge or block page instead
   * of the site. Every content-derived check then describes that interstitial,
   * so findings read from it are withheld rather than attributed to the target.
   */
  challenge?: ChallengeVerdict;
  /**
   * True when the plain HTTP client was challenged and the page was recovered
   * with the headless browser instead (see runPassiveScan). The scan is a full
   * one — the browser reached the origin — this only records how.
   */
  renderedWithBrowser?: boolean;
  // Full-transparency record of exactly which check groups ran and how many
  // discrete checks each fired against this target (see server/coverage.ts).
  coverage?: ScanCoverage;
}

export interface ScanOptions {
  // Unlocks active exploit-attempt probing (red-team fuzzing, discovered-
  // parameter fuzzing, GraphQL/BOLA probes). Defaults to false so a target
  // only receives passive black-box recon until its owner verifies it — this
  // keeps the scanner from being usable as an anonymous attack proxy against
  // arbitrary third-party sites. See server/domainVerify.ts.
  allowActiveProbes?: boolean;

  // Unlocks the AGGRESSIVE probe tier (SSTI, path traversal/LFI, open redirect,
  // CRLF injection, CORS misconfig, out-of-band XXE, NoSQL operator injection) —
  // more invasive than the standard red-team probes, so it is a separate opt-in
  // that ALSO requires allowActiveProbes (verified ownership). Still
  // non-destructive: every aggressive probe proves via oracle/signature/OOB, never
  // by writing, deleting, or degrading the target. See server/aggressiveProbes.ts.
  allowAggressiveProbes?: boolean;

  // Two owned test identities that unlock a PROVEN cross-tenant BOLA/IDOR check
  // (docs/confirmed-evidence-spec.md §3.1a). Layered on top of allowActiveProbes —
  // ownership must still be verified. When absent, the two-identity probe is
  // simply skipped (the rest of the scan is unaffected).
  bolaIdentities?: [BolaIdentity, BolaIdentity];

  // Real credentials for a discovered login form, supplied by the caller for
  // a target they own — unlocks the weak-session-token probe (one real login,
  // then an offline attempt to reproduce the resulting token from common weak
  // recipes). Layered on top of allowAggressiveProbes, like the other
  // mutating/credentialed probes. Absent → the probe is simply skipped.
  loginCredentials?: LoginCredentials;

  // Optional owner-supplied OpenAPI/Swagger spec URL. When set, the API-first
  // fuzzer fetches it directly instead of (or before) auto-discovering one at the
  // usual well-known paths — useful when the schema lives at a non-standard route.
  // Same-origin is still enforced and the operations are fuzzed under the same
  // active/aggressive gating. Absent → auto-discovery only. See server/openapi.ts.
  apiSchemaUrl?: string;

  // Out-of-band collaborator used to PROVE blind vulnerabilities: the scanner
  // injects a unique callback URL and, if the target reaches back to it, emits a
  // PROVEN 'out-of-band' finding. Threaded in by the server only when a reachable
  // public base URL is configured; when absent, the OOB probe is simply skipped.
  oob?: OobCollaborator;

  // Optional scan id, forwarded to the collaborator so a recorded callback can be
  // attributed to this scan. Purely for the audit trail.
  scanId?: string;

  // Live progress sink for the real-time ticker. When present, the pipeline
  // reports each phase and each red-team/aggressive injection as it fires (see
  // server/scanEvents.ts). Optional and side-effect-only — the scan produces the
  // exact same DiagnosticResult whether or not anyone is listening.
  emit?: EmitFn;
}
