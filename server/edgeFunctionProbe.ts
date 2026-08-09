// Edge Function auth-bypass probe (ACTIVE tier, read-only). A BaaS Edge/Serverless
// Function (Supabase, etc.) commonly lives on a DIFFERENT origin than the scanned
// app and is invoked by the app's own frontend. A frequent, severe bug: the
// function only checks that an Authorization header is PRESENT, never that the JWT
// actually verifies — so any garbage token is accepted. This proves it with a
// clean, non-destructive differential:
//   * a request with NO token is denied (401/403), yet
//   * a request with an obviously-forged token is accepted (2xx with real content).
//
// The function URL is EXTRACTED from the scanned app's own content (a
// `.../functions/v1/<name>` reference or a `functions.invoke('<name>')` call
// combined with a discovered *_URL), never guessed — the same "act on what the
// target's content actually names" principle as the credential-chaining probe.
// GET-only, like the JWT probe, so it stays idempotent/non-destructive even if a
// discovered function has side effects on other verbs. Reuses safeFetch's SSRF gate.
import { safeFetch } from "./ssrf.js";
import type { RedTeamFinding } from "./scanTypes.js";
import type { ExploitEvidence } from "../src/types.js";
import { renderRawRequest } from "./evidence.js";

const ABS_FN_RE = /(https?:\/\/[^\s"'`]+?\/functions\/v1\/[A-Za-z0-9_-]+)/g;
const REL_FN_RE = /["'`]\/functions\/v1\/([A-Za-z0-9_-]+)/g;
const INVOKE_RE = /\.functions\s*\.\s*invoke\s*\(\s*["'`]([A-Za-z0-9_-]+)["'`]/g;
const BASE_URL_RE = /\b[A-Z][A-Z0-9_]*URL\s*[=:]\s*["'`](https?:\/\/[^\s"'`]+?)["'`]/g;

// Extract candidate Edge Function URLs from served content: absolute
// .../functions/v1/<name> URLs directly, plus <name>s referenced relatively or
// via functions.invoke() combined with each discovered base URL. Bounded.
export function extractEdgeFunctionUrls(texts: string[]): string[] {
  const urls = new Set<string>();
  const names = new Set<string>();
  const bases = new Set<string>();
  for (const text of texts) {
    if (!text) continue;
    for (const re of [ABS_FN_RE]) { re.lastIndex = 0; let m; while ((m = re.exec(text))) urls.add(m[1].replace(/\/+$/, "")); }
    for (const re of [REL_FN_RE, INVOKE_RE]) { re.lastIndex = 0; let m; while ((m = re.exec(text))) names.add(m[1]); }
    BASE_URL_RE.lastIndex = 0; let bm; while ((bm = BASE_URL_RE.exec(text))) bases.add(bm[1].replace(/\/+$/, ""));
  }
  for (const base of bases) {
    for (const name of names) urls.add(`${base}/functions/v1/${name}`);
  }
  return [...urls].slice(0, 5); // bounded — catch a handful of real references, never harvest
}

async function timedGet(url: string, headers: Record<string, string>): Promise<{ res: Response; text: string }> {
  const ctl = new AbortController();
  const id = setTimeout(() => ctl.abort(), 5000);
  try {
    const res = await safeFetch(url, { method: "GET", headers, signal: ctl.signal });
    return { res, text: await res.text().catch(() => "") };
  } finally {
    clearTimeout(id);
  }
}

const DENIED = new Set([401, 403]);
const FORGED = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzZWNsYXllci1mb3JnZWQiLCJyb2xlIjoiYWRtaW4ifQ.not_a_real_signature_seclayer_probe";

export async function probeEdgeFunctionAuth(
  scannedTexts: string[],
  headers: Record<string, string>,
): Promise<RedTeamFinding | null> {
  const urls = extractEdgeFunctionUrls(scannedTexts);
  const { Authorization, authorization, ...noAuth } = headers;
  void Authorization; void authorization;

  for (const url of urls) {
    // Control: no token. Only meaningful if the function actually enforces auth.
    let control: { res: Response; text: string };
    try { control = await timedGet(url, noAuth); } catch { continue; }
    if (!DENIED.has(control.res.status)) continue; // not auth-gated here → can't prove a bypass

    // Attack: an obviously-forged token no correct verifier would accept.
    let attack: { res: Response; text: string };
    try { attack = await timedGet(url, { ...noAuth, Authorization: `Bearer ${FORGED}` }); } catch { continue; }
    if (attack.res.status < 200 || attack.res.status >= 300) continue; // correctly rejected — good

    const quote = (attack.text.trim().slice(0, 80)) || `${attack.res.status} ${attack.res.statusText}`;
    const attackResponse = `HTTP/1.1 ${attack.res.status} ${attack.res.statusText}\n\n` + (attack.text.length > 1200 ? attack.text.slice(0, 1200) + "\n[…truncated]" : attack.text);
    const evidence: ExploitEvidence = {
      method: "differential",
      attack: { request: renderRawRequest("GET", url, { ...noAuth, Authorization: `Bearer ${FORGED}` }), response: attackResponse },
      control: { request: renderRawRequest("GET", url, noAuth), response: `HTTP/1.1 ${control.res.status} ${control.res.statusText}` },
      signal: {
        quote,
        offsetInResponse: attackResponse.indexOf(quote),
        why: `With no token this Edge Function returns ${control.res.status} (auth is enforced), but it accepted an obviously-forged JWT and returned ${attack.res.status} with content — the function checks only that an Authorization header is present, never that the token verifies.`,
      },
      demonstration: `We called the Edge Function ${url} with no token and got ${control.res.status}. We then sent an obviously-forged JWT (invalid signature) and it returned ${attack.res.status} with real content. The function does not verify the token's signature, so anyone can invoke it as any user.`,
      reproduction: `curl -s -i "${url}" -H "Authorization: Bearer ${FORGED}"`,
      capturedAt: new Date().toISOString(),
    };
    return {
      testName: "Edge Function Authorization Bypass (token not verified)",
      payload: `Authorization: Bearer <forged JWT>`,
      severity: "critical",
      description:
        `A BaaS Edge Function (${url}) accepts an obviously-forged JWT: with no token it returns ${control.res.status}, but with a forged token it returns ${attack.res.status} and real content. It gates only on the PRESENCE of an Authorization header, never verifying the signature — so any attacker can invoke it and reach whatever data or action it exposes, as any user.`,
      fix: "Verify the JWT signature inside the function against the project's JWT secret/JWKS on every invocation (or require the API gateway's verify_jwt and re-check claims). Never treat the mere presence of an Authorization header as authentication.",
      evidence,
    };
  }
  return null;
}
