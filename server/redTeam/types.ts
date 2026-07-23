// Shared contracts for the individual red-team probes. Each probe is a pure
// async function that takes a ProbeContext and resolves to a single
// RedTeamFinding when it PROVES a vulnerability, or null when the target is not
// exploitable by that technique. The orchestrator (../redTeamProbes.ts) runs
// them and isolates each one's failures so a single thrown probe never aborts
// the rest.
import type { OobCollaborator } from "../oob.js";
import type { RedTeamFinding } from "../scanTypes.js";

export type { RedTeamFinding } from "../scanTypes.js";

export interface ProbeContext {
  // Target root URL (already normalized to include a scheme).
  url: string;
  // The scanner's request headers, with a no-cache directive added for fuzzing.
  fuzzHeaders: Record<string, string>;
  // Out-of-band collaborator, present only for the blind-SSRF probe.
  oob?: OobCollaborator;
  scanId?: string;
}

export type Probe = (ctx: ProbeContext) => Promise<RedTeamFinding | null>;
