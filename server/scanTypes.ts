// Shared scan data contracts: the DiagnosticResult produced by runDiagnostics
// and the ScanOptions that configure it. Extracted so the probe/analysis modules
// can depend on the shapes without importing the scanner entry point.
import type { Finding, Severity, ExploitEvidence, BolaIdentity } from "../src/types.js";
import type { OobCollaborator } from "./oob.js";

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
}

export interface DiagnosticResult {
  url: string;
  scannedAt: string;
  responseStatus: number;
  sslSecure: boolean;
  headers: Record<string, string>;
  missingHeaders: string[];
  techLeaked: string[];
  probedPaths: Array<{ path: string; status: number; exposed: boolean }>;
  cookieIssues: string[];

  // High-fidelity AppSec dimensions
  sastFindings: Array<{
    file: string;
    issue: string;
    severity: Severity;
    confidence: "low" | "medium" | "high";
    type: string;
    fix: string;
    description: string;
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
  }>;
  // True when active exploit probing (SQLi/XSS/cmd-injection/SSRF/GraphQL/BOLA
  // fuzzing) was skipped because the target's domain ownership isn't verified.
  activeProbesSkipped?: boolean;
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

  // Out-of-band collaborator used to PROVE blind vulnerabilities: the scanner
  // injects a unique callback URL and, if the target reaches back to it, emits a
  // PROVEN 'out-of-band' finding. Threaded in by the server only when a reachable
  // public base URL is configured; when absent, the OOB probe is simply skipped.
  oob?: OobCollaborator;

  // Optional scan id, forwarded to the collaborator so a recorded callback can be
  // attributed to this scan. Purely for the audit trail.
  scanId?: string;
}
