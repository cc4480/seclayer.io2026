// Missing-rate-limit probe for OTP / 2FA verification endpoints (AGGRESSIVE tier).
//
// UNLIKE every other probe in this codebase, this one CANNOT positively prove
// its finding: it observes the ABSENCE of a control, and you can never prove a
// negative from a bounded number of samples ("no throttle in N tries" ≠ "no
// throttle exists"). It is therefore reported at MEDIUM confidence (needs
// verification), never PROVEN. It stays as accurate and low-invasive as possible:
//   * Only a SMALL bounded burst of wrong codes (BURST attempts, matching OTP
//     best-practice thresholds of 3-5, so a correctly-limited endpoint trips
//     well within it), never a real brute-force.
//   * A correctly-limited endpoint is detected reliably: express-rate-limit and
//     most gateways emit RateLimit-*/Retry-After headers (often on the FIRST
//     response) and/or a 429 — any of which means "throttled" → no finding.
//   * Precondition: the endpoint must consistently REJECT wrong codes with a 4xx
//     (so it really is a verify endpoint processing our attempts); a 404 or a
//     2xx-accepts-anything response is skipped, not flagged.
// Residual reasons it stays MEDIUM: a limiter that emits no headers and whose
// threshold exceeds the burst would be missed, and a real OTP endpoint may
// reject our attempts for lack of a pending-session context (looking like "no
// throttle") — both are why absence-of-limit is inherently a heuristic.
import { safeFetch } from "./ssrf.js";
import type { RedTeamFinding } from "./scanTypes.js";

const BURST = 6;
const VERIFY_PATHS = [
  "/api/auth/verify-sms", "/api/auth/verify-otp", "/api/verify-otp", "/api/verify-sms",
  "/api/2fa/verify", "/api/mfa/verify", "/api/auth/verify-code", "/api/verify-code",
  "/api/otp/verify", "/verify-otp", "/api/auth/2fa/verify",
];
const VERIFY_HINT = /(verify|otp|2fa|mfa|totp)/i;
const THROTTLE_HEADER = /^(ratelimit-|x-ratelimit-|retry-after)/i;
const THROTTLE_BODY = /too many|rate.?limit|try again (?:later|in)|slow down|locked|throttl/i;
const REJECTION = new Set([400, 401, 403, 422]);

const bodyFor = (n: number) => {
  const code = String(100000 + n); // a distinct, wrong 6-digit code per attempt
  return JSON.stringify({ phoneNumber: "+15555550100", code, otp: code });
};

async function postAttempt(url: string, headers: Record<string, string>, n: number): Promise<{ status: number; throttled: boolean }> {
  const ctl = new AbortController();
  const id = setTimeout(() => ctl.abort(), 5000);
  try {
    const res = await safeFetch(url, {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/json" },
      body: bodyFor(n),
      signal: ctl.signal,
    });
    const text = await res.text().catch(() => "");
    let headerThrottle = false;
    res.headers.forEach((_v, k) => { if (THROTTLE_HEADER.test(k)) headerThrottle = true; });
    const throttled = res.status === 429 || headerThrottle || THROTTLE_BODY.test(text);
    return { status: res.status, throttled };
  } finally {
    clearTimeout(id);
  }
}

export async function probeAuthRateLimit(
  rootUrl: string,
  postUrls: string[],
  headers: Record<string, string>,
): Promise<RedTeamFinding | null> {
  const base = rootUrl.replace(/\/+$/, "");
  const candidates = [
    ...new Set([
      ...VERIFY_PATHS.map((p) => `${base}${p}`),
      ...postUrls.filter((u) => VERIFY_HINT.test(u)),
    ]),
  ];

  for (const url of candidates) {
    // First attempt establishes the precondition: a real verify endpoint that
    // REJECTS a wrong code (4xx) and isn't already throttling.
    let first: { status: number; throttled: boolean };
    try { first = await postAttempt(url, headers, 0); } catch { continue; }
    if (first.throttled) continue;          // already rate-limited → safe, no finding
    if (!REJECTION.has(first.status)) continue; // 404 (no endpoint) or 2xx (accepts anything) → not a testable verify endpoint

    // Fire the rest of the bounded burst; bail the moment ANY throttle appears.
    let throttledAt = 0;
    let consistent = true;
    for (let n = 1; n < BURST; n++) {
      let r: { status: number; throttled: boolean };
      try { r = await postAttempt(url, headers, n); } catch { consistent = false; break; }
      if (r.throttled) { throttledAt = n + 1; break; }
      if (!REJECTION.has(r.status)) { consistent = false; break; } // response shape changed → ambiguous, don't flag
    }
    if (throttledAt > 0 || !consistent) continue; // throttled or ambiguous → no finding

    // All BURST wrong-code attempts were rejected identically with NO throttling
    // signal (no 429, no RateLimit-*/Retry-After header, no throttle text).
    return {
      testName: "No Rate Limiting on Authentication-Code Verification",
      payload: `${BURST}× wrong-code POST to ${url}`,
      severity: "high",
      confidence: "medium", // observational (absence of a control) — reported as needs-verification, never PROVEN
      description:
        `A verification endpoint (${url}) accepted ${BURST} rapid wrong-code attempts in a row with no throttling of any kind — no 429, no RateLimit-*/Retry-After headers, no lockout — so an attacker can brute-force the code space (a 6-digit OTP is only 1e6 possibilities) offline-fast. Reported at MEDIUM confidence: absence of a rate limit cannot be positively proven from a bounded number of attempts, and a real endpoint may also require a pending-verification session this black-box probe cannot establish — verify manually that a legitimate code is in play.`,
      fix: "Rate-limit verification attempts per account/phone/IP (e.g. 3-5 tries then a timed lockout with exponential backoff), invalidate the code after a few failures and force reissue, and cap the code's lifetime. express-rate-limit or an equivalent gateway limiter on the verify route is the minimum.",
    };
  }
  return null;
}
