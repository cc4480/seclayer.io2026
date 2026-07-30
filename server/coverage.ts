// Full-transparency scan-coverage accounting. Builds the per-scan record of
// exactly which check groups ran against a target and how many discrete checks
// each fired — from the real run, using the same probe arrays the scanner
// executes (so the numbers can't drift from what actually happened). Gated groups
// (ownership-required exploit probes, the aggressive opt-in) are listed with
// their would-run count and ran:false + a reason, so a report can show both what
// ran and what's available once the domain is verified.
import type { ScanCoverage, ScanCoverageItem } from "../src/types.js";
import { SECURITY_HEADERS } from "./passiveScan.js";
import { SECRET_SIGNATURE_COUNT, LIBRARY_SIGNATURE_COUNT } from "./staticAnalysis.js";
import { RED_TEAM_PROBE_COUNT } from "./redTeamProbes.js";
import { AGGRESSIVE_PROBE_COUNT } from "./aggressiveProbes.js";
import { API_PROBE_COUNT } from "./apiProbes.js";

const OWNERSHIP_NOTE = "requires verified domain ownership";
const AGGRESSIVE_NOTE = "requires the aggressive opt-in + verified ownership";

export interface CoverageInputs {
  activeProbesRun: boolean;
  aggressiveProbesRun: boolean;
  subdomainsChecked: number;
  pathsProbed: number;
  templatesRun: number;
  crawlPages: number;
  paramsFuzzed: number;
  domXssRun: boolean;
}

export function buildScanCoverage(p: CoverageInputs): ScanCoverage {
  const active = p.activeProbesRun;
  const aggressive = p.aggressiveProbesRun;

  const items: ScanCoverageItem[] = [
    // --- Passive tier: always runs ---
    { label: "Security response headers", category: "IAST", checks: SECURITY_HEADERS.length, ran: true },
    { label: "Cookie security flags (Secure, HttpOnly)", category: "IAST", checks: 2, ran: true },
    { label: "TLS / HTTPS transport", category: "EASM", checks: 1, ran: true },
    { label: "DNS resolution (A record + nameserver)", category: "EASM", checks: 2, ran: true },
    { label: "Subdomain enumeration", category: "EASM", checks: p.subdomainsChecked, ran: p.subdomainsChecked > 0 },
    { label: "Exposed-secret signatures (SAST)", category: "SAST", checks: SECRET_SIGNATURE_COUNT, ran: true },
    { label: "Vulnerable-library signatures (SCA)", category: "SCA", checks: LIBRARY_SIGNATURE_COUNT, ran: true },
    { label: "Sensitive-path probing", category: "DAST", checks: p.pathsProbed, ran: p.pathsProbed > 0 },
    { label: "Template detection pack (tech-gated)", category: "DAST", checks: p.templatesRun, ran: p.templatesRun > 0 },
    { label: "Crawl / surface mapping (pages)", category: "DAST", checks: p.crawlPages, ran: p.crawlPages > 0 },

    // --- Active exploit tier: gated behind verified ownership ---
    {
      label: "Red-team exploit probes (root URL): SQLi, XSS, cmd-injection, SSRF, blind SSRF",
      category: "RED_TEAM", checks: RED_TEAM_PROBE_COUNT, ran: active, note: active ? undefined : OWNERSHIP_NOTE,
    },
    {
      label: "Discovered-parameter injection fuzzing",
      category: "RED_TEAM", checks: p.paramsFuzzed, ran: active && p.paramsFuzzed > 0,
      note: active ? undefined : OWNERSHIP_NOTE,
    },
    {
      label: "API security probes: GraphQL introspection, exposed-object, BOLA/IDOR",
      category: "API_SEC", checks: API_PROBE_COUNT, ran: active, note: active ? undefined : OWNERSHIP_NOTE,
    },
    {
      label: "JWT auth-weakness probe",
      category: "RED_TEAM", checks: 1, ran: active,
      note: active ? "fires only when a Bearer JWT is supplied" : OWNERSHIP_NOTE,
    },
    {
      label: "DOM-based XSS (headless execution proof)",
      category: "RED_TEAM", checks: 1, ran: p.domXssRun,
      note: p.domXssRun ? undefined : "requires ownership + ENABLE_BROWSER_RENDERING",
    },

    // --- Aggressive tier: explicit opt-in + ownership ---
    {
      label: "Aggressive injection tier: SSTI, LFI, XXE, CORS, CRLF, open-redirect, NoSQL, host-header",
      category: "RED_TEAM", checks: AGGRESSIVE_PROBE_COUNT, ran: aggressive, note: aggressive ? undefined : AGGRESSIVE_NOTE,
    },
    {
      label: "Stored/persistent XSS (discovered forms)",
      category: "RED_TEAM", checks: 1, ran: aggressive, note: aggressive ? undefined : AGGRESSIVE_NOTE,
    },
  ];

  const totalChecks = items.reduce((sum, it) => sum + (it.ran ? it.checks : 0), 0);
  return { totalChecks, activeProbesRun: active, aggressiveProbesRun: aggressive, items };
}
