// Out-of-band (blind) SSRF probe. Reflection only catches SSRF that echoes
// internal content back inline; this catches the blind case by injecting a
// unique collaborator URL and watching for the target to call it. A recorded
// callback is the proof — see server/oob.ts and buildOobEvidence. Runs only
// when an out-of-band collaborator is configured.
import { buildOobEvidence } from "../evidence.js";
import { probeFetch } from "./probeHttp.js";
import type { ProbeContext, RedTeamFinding } from "./types.js";

export async function probeBlindSsrf(ctx: ProbeContext): Promise<RedTeamFinding | null> {
  if (!ctx.oob) return null;

  const probe = ctx.oob.issue(ctx.scanId);
  const attackUrl = `${ctx.url}/?url=${encodeURIComponent(probe.url)}`;

  // Fire the trigger: ask the target to fetch our collaborator URL. The target
  // may not respond to us directly — the callback is the proof — so a failure
  // here is expected and ignored.
  try {
    await probeFetch(attackUrl, ctx.fuzzHeaders);
  } catch {
    /* the target may not respond to us directly — the callback is the proof */
  }

  // Wait a bounded window for the target to reach our collaborator.
  const event = await ctx.oob.poll(probe.token, 8000);
  if (!event) return null;

  return {
    testName: "Blind Server-Side Request Forgery (out-of-band)",
    payload: probe.url,
    severity: "critical",
    description:
      "The target fetched a unique Seclayer collaborator URL supplied in the \"url\" parameter, reaching our out-of-band listener from its own infrastructure. This proves the server makes attacker-controlled outbound requests even though nothing is reflected in its response — a blind SSRF that can be aimed at internal services or cloud metadata.",
    fix: "Do not fetch user-supplied URLs directly. Enforce an allow-list of permitted hosts, resolve and validate the destination IP (blocking loopback/link-local/RFC1918/metadata ranges), and disable redirects to internal addresses.",
    evidence: buildOobEvidence({
      attackUrl,
      requestHeaders: ctx.fuzzHeaders,
      callbackUrl: probe.url,
      token: probe.token,
      event,
      why: "This is our collaborator's record of the target calling the unique, unguessable URL we injected. Only a server that fetched our payload URL could produce this callback — a public visitor cannot forge it.",
      demonstration: `We put a one-time Seclayer URL in the "url" parameter, and moments later the target itself connected to that URL from ${event.sourceIp}. That callback — carrying our unique token — proves the server made a request we controlled, without leaking anything in its own response.`,
    }),
  };
}
