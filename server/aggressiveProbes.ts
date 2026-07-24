// AGGRESSIVE tier orchestrator. A more invasive, opt-in layer on top of the
// standard red-team probes: SSTI, path traversal/LFI, open redirect, CRLF /
// response-header injection, CORS misconfiguration, out-of-band XXE, and NoSQL
// operator injection. Every probe here is still NON-DESTRUCTIVE and
// signature/oracle/OOB-proven (never a status code alone), and — like the
// red-team tier — is gated behind verified domain ownership AND an explicit
// per-scan aggressive opt-in (see ScanOptions.allowAggressiveProbes). Each probe
// is isolated so one failure never aborts the rest.
import type { OobCollaborator } from "./oob.js";
import type { Probe, ProbeContext, RedTeamFinding } from "./redTeam/types.js";
import { probeSsti } from "./aggressive/ssti.js";
import { probePathTraversal } from "./aggressive/pathTraversal.js";
import { probeOpenRedirect } from "./aggressive/openRedirect.js";
import { probeCrlf } from "./aggressive/crlfInjection.js";
import { probeCors } from "./aggressive/cors.js";
import { probeXxe } from "./aggressive/xxe.js";
import { probeNoSql } from "./aggressive/nosql.js";

const PROBES: Probe[] = [
  probeSsti,
  probePathTraversal,
  probeOpenRedirect,
  probeCrlf,
  probeCors,
  probeXxe,
  probeNoSql,
];

export async function runAggressiveProbes(
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
      console.warn(`[aggressive] probe ${probe.name} failed:`, err);
    }
  }
  return findings;
}
