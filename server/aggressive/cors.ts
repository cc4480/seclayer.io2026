// CORS misconfiguration active probe (AGGRESSIVE tier). Sends a request with an
// attacker Origin and checks whether the app REFLECTS that exact origin in
// Access-Control-Allow-Origin while also allowing credentials — the combination
// that lets any malicious site read authenticated responses on behalf of a
// logged-in victim. Non-destructive: one GET with a forged Origin header.
import { aggFetch, buildHeaderEvidence } from "./aggHttp.js";
import type { ProbeContext, RedTeamFinding } from "../redTeam/types.js";

const EVIL_ORIGIN = "https://seclayer-cors-probe.example";

export async function probeCors(ctx: ProbeContext): Promise<RedTeamFinding | null> {
  const attackUrl = `${ctx.url}/`;
  let res: Response;
  try {
    res = await aggFetch(attackUrl, { headers: { ...ctx.fuzzHeaders, Origin: EVIL_ORIGIN } });
  } catch {
    return null;
  }
  const acao = res.headers.get("access-control-allow-origin") || "";
  const acac = (res.headers.get("access-control-allow-credentials") || "").toLowerCase();

  // Exploitable case: the server reflects our arbitrary origin verbatim AND
  // allows credentials. (ACAO:* with credentials is ignored by browsers, so it
  // is NOT the dangerous case and is deliberately not flagged here.)
  if (acao === EVIL_ORIGIN && acac === "true") {
    return {
      testName: "Active CORS Misconfiguration (origin reflection + credentials)",
      payload: `Origin: ${EVIL_ORIGIN}`,
      severity: "high",
      description:
        "Active Red Team probing found the server reflects an arbitrary request Origin into Access-Control-Allow-Origin while also sending Access-Control-Allow-Credentials: true. Any attacker-controlled website can then make credentialed cross-origin requests and read the authenticated responses of a logged-in victim.",
      fix: "Never reflect the Origin header. Validate the request Origin against a strict allow-list of trusted origins and only then echo it; never combine a wildcard or reflected origin with Access-Control-Allow-Credentials: true.",
      evidence: buildHeaderEvidence({
        method: "reflection",
        reqMethod: "GET",
        attackUrl,
        requestHeaders: { ...ctx.fuzzHeaders, Origin: EVIL_ORIGIN },
        res,
        proofHeaders: [
          `Access-Control-Allow-Origin: ${acao}`,
          `Access-Control-Allow-Credentials: ${res.headers.get("access-control-allow-credentials")}`,
        ],
        quote: EVIL_ORIGIN,
        why: `We sent "Origin: ${EVIL_ORIGIN}" and the server echoed that exact origin back in Access-Control-Allow-Origin with credentials allowed. A browser will therefore let ${EVIL_ORIGIN} read this site's authenticated responses.`,
        demonstration: `We claimed to be "${EVIL_ORIGIN}" via the Origin header and the server told the browser that origin is trusted (with credentials). A page an attacker controls could read your users' logged-in data cross-origin.`,
      }),
    };
  }
  return null;
}
