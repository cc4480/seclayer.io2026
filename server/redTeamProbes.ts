// RED TEAM active fuzzing — real exploit payloads (SQLi / reflected XSS / OS
// command injection / SSRF, both reflected and blind out-of-band) fired at the
// root URL. Every hit carries a PROVEN receipt whose signal is a literal
// substring of the captured response (or, for blind SSRF, the recorded
// collaborator callback). Caller gates invocation on verified domain ownership.
//
// This module is the orchestrator: each technique lives in its own file under
// ./redTeam/ as an independently-testable probe. runDueMonitoredScans-style
// isolation is applied here — a single probe throwing (a network error, a
// malformed response) never aborts the others or the scan.
import type { OobCollaborator } from "./oob.js";
import type { Probe, ProbeContext, RedTeamFinding } from "./redTeam/types.js";
import { probeSqlInjection } from "./redTeam/sqlInjection.js";
import { probeReflectedXss } from "./redTeam/reflectedXss.js";
import { probeCommandInjection } from "./redTeam/commandInjection.js";
import { probeSsrf } from "./redTeam/ssrf.js";
import { probeBlindSsrf } from "./redTeam/blindSsrf.js";

// Ordered exactly as before: SQLi → XSS → cmd injection → reflected SSRF → blind
// OOB SSRF. probeBlindSsrf no-ops on its own when no collaborator is configured.
const PROBES: Probe[] = [
  probeSqlInjection,
  probeReflectedXss,
  probeCommandInjection,
  probeSsrf,
  probeBlindSsrf,
];

export async function runRedTeamProbes(
  url: string,
  headers: Record<string, string>,
  opts: { oob?: OobCollaborator; scanId?: string } = {},
): Promise<RedTeamFinding[]> {
  const ctx: ProbeContext = {
    url,
    fuzzHeaders: { ...headers, "Cache-Control": "no-cache" },
    oob: opts.oob,
    scanId: opts.scanId,
  };

  const findings: RedTeamFinding[] = [];
  for (const probe of PROBES) {
    try {
      const finding = await probe(ctx);
      if (finding) findings.push(finding);
    } catch (err) {
      // One probe's failure (fetch error, malformed response) must never stop
      // the rest. The original inline version swallowed each probe's errors the
      // same way; the log line preserves that visibility.
      console.warn(`[redteam] probe ${probe.name} failed:`, err);
    }
  }
  return findings;
}
