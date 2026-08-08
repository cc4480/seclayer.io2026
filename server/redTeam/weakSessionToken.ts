// Session-token predictability probe. Detects the common "hash(low-entropy
// seed)" weak-session pattern — e.g. MD5(username + unix-timestamp) — which
// LOOKS like a random token (a hash's output is always uniformly
// distributed) but is fully reproducible by anyone who knows the username
// and the approximate login time.
//
// Deliberately NOT generic statistical "randomness testing" of the token:
// that technique cannot tell a weak-seed hash apart from a real CSPRNG
// output (hashing destroys the input's own statistical structure), so it
// would give a false sense of coverage on exactly the pattern this targets.
// Instead this is a targeted, zero-false-positive reproduction attempt: log
// in ONCE with credentials the CALLER already supplied (never guessed or
// brute-forced — this only runs when the caller explicitly opts in with
// real credentials for a target they own), capture the resulting token, then
// try to recompute it OFFLINE from a small set of common (seed, algorithm)
// combinations across a short timestamp window around the real request. An
// exact byte-for-byte match is definitive: the odds of a spurious collision
// across a few dozen candidates against a 128+ bit hash are negligible, so a
// match is proof, not a guess.
import crypto from "crypto";
import type { InjectableTarget } from "../crawler.js";
import { safeFetch } from "../ssrf.js";
import { renderRawRequest } from "../evidence.js";
import type { ExploitEvidence, LoginCredentials, Severity } from "../../src/types.js";

const USERNAME_FIELD = /\b(username|email|user|login|uid)\b/i;
const PASSWORD_FIELD = /\b(password|passwd|pwd|pass)\b/i;

// Finds the first discovered POST target that looks like a login form (has
// both a username-shaped and a password-shaped field).
export function findLoginTarget(targets: InjectableTarget[]): InjectableTarget | null {
  return (
    targets.find(
      (t) =>
        t.method === "POST" &&
        t.params.some((p) => USERNAME_FIELD.test(p)) &&
        t.params.some((p) => PASSWORD_FIELD.test(p)),
    ) || null
  );
}

const TOKEN_FIELD = /^(token|sessiontoken|sessionid|session|sid|accesstoken|auth)$/i;

// Pulls a session-token-shaped string out of a login response: a JSON body
// field with a token-ish name, or (failing that) the first Set-Cookie value.
export function extractToken(bodyText: string, contentType: string, setCookie: string[]): string | null {
  if (/application\/json/i.test(contentType)) {
    try {
      const obj = JSON.parse(bodyText);
      if (obj && typeof obj === "object") {
        for (const [k, v] of Object.entries(obj)) {
          if (TOKEN_FIELD.test(k) && typeof v === "string" && v.length >= 8) return v;
        }
      }
    } catch {
      /* not JSON */
    }
  }
  if (setCookie.length) {
    const m = setCookie[0].match(/^\s*[^=;\s]+=([^;]+)/);
    if (m && m[1].length >= 8) return m[1];
  }
  return null;
}

// hex-digest length -> the hash algorithm(s) that produce it. Narrows the
// search space (and skips non-hex tokens like JWTs/UUIDs/base64 entirely —
// correctly, since this technique only applies to raw hex digest tokens).
const ALGOS_BY_HEX_LEN: Record<number, string[]> = {
  32: ["md5"],
  40: ["sha1"],
  64: ["sha256"],
};

// A handful of common ways an app might combine a known seed value (the
// username) with a timestamp. Deliberately small — a targeted check for a
// specific, common pattern, not a brute-force wordlist.
function candidateSeeds(username: string, ts: number): string[] {
  const t = String(ts);
  return [`${username}${t}`, `${t}${username}`, `${username}:${t}`, `${username}-${t}`, `${username}_${t}`];
}

export async function probeWeakSessionToken(
  loginTarget: InjectableTarget,
  credentials: LoginCredentials,
  headers: Record<string, string>,
): Promise<{ testName: string; payload: string; severity: Severity; description: string; fix: string; evidence: ExploitEvidence } | null> {
  const usernameField = loginTarget.params.find((p) => USERNAME_FIELD.test(p));
  const passwordField = loginTarget.params.find((p) => PASSWORD_FIELD.test(p));
  if (!usernameField || !passwordField) return null;

  const isJson = loginTarget.contentType === "json";
  const body = isJson
    ? JSON.stringify({ [usernameField]: credentials.username, [passwordField]: credentials.password })
    : new URLSearchParams({ [usernameField]: credentials.username, [passwordField]: credentials.password }).toString();
  const reqHeaders = { ...headers, "Content-Type": isJson ? "application/json" : "application/x-www-form-urlencoded" };

  const preSendMs = Date.now();
  let res: Response;
  try {
    const ctl = new AbortController();
    const id = setTimeout(() => ctl.abort(), 6000);
    try {
      res = await safeFetch(loginTarget.url, { method: "POST", headers: reqHeaders, body, signal: ctl.signal });
    } finally {
      clearTimeout(id);
    }
  } catch {
    return null; // login unreachable — not applicable, not a finding
  }
  const postReceiveMs = Date.now();

  const bodyText = await res.text().catch(() => "");
  const contentType = res.headers.get("content-type") || "";
  const setCookie: string[] =
    typeof (res.headers as any).getSetCookie === "function" ? (res.headers as any).getSetCookie() : [];

  const token = extractToken(bodyText, contentType, setCookie);
  if (!token) return null; // couldn't identify a session token — not applicable

  const hexToken = /^[0-9a-f]+$/i.test(token) ? token.toLowerCase() : null;
  const algos = hexToken ? ALGOS_BY_HEX_LEN[hexToken.length] || [] : [];
  if (!hexToken || !algos.length) return null; // not a hex digest at a length we recognize

  // Window covers request-send → response-receive, padded generously for
  // clock skew and latency — local/CI requests are sub-second, so even a
  // generous pad keeps the candidate count small (a handful of seconds).
  const PAD_SECONDS = 5;
  const startSec = Math.floor(preSendMs / 1000) - PAD_SECONDS;
  const endSec = Math.floor(postReceiveMs / 1000) + PAD_SECONDS;

  for (let ts = startSec; ts <= endSec; ts++) {
    for (const seed of candidateSeeds(credentials.username, ts)) {
      for (const algo of algos) {
        const candidate = crypto.createHash(algo).update(seed).digest("hex");
        if (candidate !== hexToken) continue;

        // Exact match — definitive proof. The "attack" is the offline hash
        // computation, shown as a reproducible recipe; no second live
        // request is needed since the match against the real token already
        // proves reproducibility.
        const recipe = `${algo}("${seed}") === ${hexToken}`;
        return {
          testName: "Predictable Session Token (Weak Seed Hash)",
          payload: recipe,
          severity: "critical",
          description: `The session token returned by ${loginTarget.url} is ${algo.toUpperCase()}("${usernameField}" + a Unix timestamp) — anyone who knows a user's ${usernameField} and the approximate login time can compute the exact same token offline and hijack the session. The hash output looks random; the INPUT it's derived from is not.`,
          fix: "Generate session tokens from a cryptographically secure random source (e.g. crypto.randomBytes(32)), never by hashing predictable values like a username or timestamp. Store only a hash of the token server-side and compare in constant time.",
          evidence: {
            method: "oracle",
            attack: {
              request: renderRawRequest("POST", loginTarget.url, reqHeaders, body),
              response: `The real login response returned this session token:\n${hexToken}\n\nRecomputed entirely offline: ${recipe}`,
            },
            signal: {
              quote: hexToken,
              offsetInResponse: 0,
              why: `We computed ${algo.toUpperCase()}("${seed}") completely offline (no further interaction with the target) and it matches the captured token byte-for-byte. Reproducing a token exactly requires knowing its generation recipe — this proves the recipe is "${algo}(username + timestamp)", not a secure random source.`,
            },
            demonstration: `We logged in once and captured session token ${hexToken}. Trying common weak-token recipes offline, ${algo.toUpperCase()}("${seed}") produced the exact same value — proving the token is a hash of a predictable seed (the username and the login's own timestamp), not cryptographically random.`,
            // Single-quoted JS string literal for the seed (escaping any embedded
            // single quotes) so this stays copy-pasteable as one shell argument —
            // JSON.stringify's double-quoted output would collide with the outer
            // double-quoted -e argument the moment the seed contains no quotes to
            // escape but is itself wrapped in "..." inside an already-"..." command.
            reproduction: `node -e "console.log(require('crypto').createHash('${algo}').update('${seed.replace(/'/g, "\\'")}').digest('hex'))"`,
            capturedAt: new Date().toISOString(),
          },
        };
      }
    }
  }
  return null; // no match within the window — not reproducible via this common pattern
}
