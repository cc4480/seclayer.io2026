// RED TEAM active fuzzing suite — real exploit payloads (SQLi / reflected XSS /
// OS command injection / SSRF, both reflected and blind out-of-band) fired at
// the root URL. Every hit carries a PROVEN receipt whose signal is a literal
// substring of the captured response (or, for blind SSRF, the recorded
// collaborator callback). Caller gates invocation on verified domain ownership.
// The individual probes live in ./injectionProbes.js and ./ssrfProbes.js.
import type { OobCollaborator } from "./oob.js";
import { probeSqlInjection, probeReflectedXss, probeCommandInjection } from "./injectionProbes.js";
import { probeSsrfReflected, probeBlindSsrf } from "./ssrfProbes.js";

export async function runRedTeamProbes(
  url: string,
  headers: Record<string, string>,
  opts: { oob?: OobCollaborator; scanId?: string } = {},
): Promise<any[]> {
  const findings: any[] = [];
  try {
    const fuzzHeaders = { ...headers, "Cache-Control": "no-cache" };

    // Each probe returns a finding or null, and swallows its own errors.
    for (const probe of [probeSqlInjection, probeReflectedXss, probeCommandInjection, probeSsrfReflected]) {
      const finding = await probe(url, fuzzHeaders);
      if (finding) findings.push(finding);
    }

    if (opts.oob) {
      const finding = await probeBlindSsrf(url, fuzzHeaders, opts.oob, opts.scanId);
      if (finding) findings.push(finding);
    }
  } catch (globalErr) {
    console.warn("Red team active fuzzing encounted top-level error", globalErr);
  }
  return findings;
}
