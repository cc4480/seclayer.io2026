// Host header injection active probe (AGGRESSIVE tier). Sends an attacker-
// controlled X-Forwarded-Host and checks whether the app trusts it to build
// absolute URLs — reflected into a redirect Location (password-reset / email-link
// poisoning) or into the response body (web cache poisoning). Non-destructive:
// one GET carrying a forged forwarding header. The proof is the unique marker
// host reflected where only the real, server-configured host should appear.
import crypto from "crypto";
import { aggFetchRaw, buildHeaderEvidence } from "./aggHttp.js";
import { buildProbeEvidence } from "../evidence.js";
import type { ProbeContext, RedTeamFinding } from "../redTeam/types.js";

export async function probeHostHeaderInjection(ctx: ProbeContext): Promise<RedTeamFinding | null> {
  const marker = `seclayer-hhi-${crypto.randomBytes(4).toString("hex")}.example`;
  const attackUrl = `${ctx.url}/`;
  const headers = { ...ctx.fuzzHeaders, "X-Forwarded-Host": marker };

  let res: Response;
  try {
    // Raw (no redirect follow) so a 3xx Location built from our header survives.
    res = await aggFetchRaw(attackUrl, { headers });
  } catch {
    return null;
  }

  // 1) Reflected into a redirect Location — the strongest case: the app builds
  //    absolute links (password-reset emails, redirects) from X-Forwarded-Host,
  //    so an attacker can point those links at a host they control.
  const location = res.headers.get("location") || "";
  if (location.includes(marker)) {
    return {
      testName: "Host Header Injection (redirect via X-Forwarded-Host)",
      payload: `X-Forwarded-Host: ${marker}`,
      severity: "high",
      description:
        "The application trusts the client-supplied X-Forwarded-Host header to build absolute URLs: an attacker-controlled host was reflected into a redirect Location. This enables password-reset poisoning (reset links pointing at the attacker) and phishing redirects.",
      fix: "Never derive absolute URLs (redirects, email links, canonical tags) from client-supplied Host / X-Forwarded-Host headers. Use a fixed, server-configured canonical host, or validate the header against a strict allow-list.",
      evidence: buildHeaderEvidence({
        method: "reflection",
        reqMethod: "GET",
        attackUrl,
        requestHeaders: headers,
        res,
        proofHeaders: [`Location: ${location}`],
        quote: marker,
        why: `We sent "X-Forwarded-Host: ${marker}" and the server built its redirect Location from it, pointing at a host we control.`,
        demonstration: `We set X-Forwarded-Host to "${marker}" and the server redirected to a URL on that attacker-controlled host — the hallmark of host-header injection (e.g. password-reset link poisoning).`,
      }),
    };
  }

  // 2) Reflected into an absolute URL in the body (canonical tag, script/link
  //    hrefs) — a web-cache-poisoning surface on cacheable endpoints.
  const body = await res.text().catch(() => "");
  const idx = body.indexOf(marker);
  if (idx !== -1) {
    return {
      testName: "Host Header Injection (reflected via X-Forwarded-Host)",
      payload: `X-Forwarded-Host: ${marker}`,
      severity: "medium",
      description:
        "The application reflects the client-supplied X-Forwarded-Host header into absolute URLs in its response (e.g. canonical tags, script/link hrefs). On a cacheable endpoint this enables web cache poisoning — serving other users resources that point at an attacker-controlled host.",
      fix: "Never build absolute URLs from client-supplied Host / X-Forwarded-Host headers; use a fixed canonical host. If a reverse proxy legitimately sets X-Forwarded-Host, validate it against an allow-list before trusting it.",
      evidence: buildProbeEvidence({
        method: "reflection",
        attackUrl,
        requestHeaders: headers,
        res,
        body,
        matchIndex: idx,
        quote: marker,
        why: `We sent "X-Forwarded-Host: ${marker}" and the server echoed that attacker-controlled host into an absolute URL in the response body.`,
        demonstration: `We set X-Forwarded-Host to "${marker}" and the server reflected it into its page (e.g. a canonical/link URL) — a web-cache-poisoning vector.`,
      }),
    };
  }

  return null;
}
