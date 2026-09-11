/**
 * Verify a Svix-signed webhook, which is how Resend signs its delivery events.
 *
 * Implemented here rather than pulling in the `svix` package: the scheme is
 * three headers and one HMAC, and a webhook that can mark addresses
 * undeliverable is not somewhere to add dependency surface for thirty lines of
 * crypto.
 *
 * WHY THIS MUST BE VERIFIED AT ALL. The endpoint it guards writes to the
 * suppression list. Unauthenticated, anyone who found the URL could POST a
 * forged "hard bounce" for any address and permanently stop that person
 * receiving sign-in codes — a denial-of-service against a named account, with
 * no login required and nothing in the logs that looks wrong.
 *
 * The scheme (https://docs.svix.com/receiving/verifying-payloads):
 *   signed content = `${svix-id}.${svix-timestamp}.${raw body}`
 *   signature      = base64(HMAC-SHA256(base64decode(secret), signed content))
 *   svix-signature = space-delimited list of `v1,<signature>` (several during
 *                    a secret rotation, any one of which may match)
 */

import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * How far out of step a webhook's timestamp may be.
 *
 * Without this, a signature stays valid forever and a captured request can be
 * replayed indefinitely — re-suppressing an address the user has since fixed.
 * Five minutes each way is Svix's own tolerance and covers ordinary clock drift.
 */
export const TIMESTAMP_TOLERANCE_SECONDS = 5 * 60;

export type SvixFailure =
  | "missing_headers"
  | "bad_timestamp"
  | "timestamp_out_of_tolerance"
  | "no_signatures"
  | "no_match";

export type SvixResult = { ok: true } | { ok: false; reason: SvixFailure };

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/**
 * @param secret The endpoint secret, as Resend shows it (`whsec_…`). The prefix
 *               is stripped; what follows is base64 and is the actual HMAC key.
 * @param rawBody The body EXACTLY as received. Re-serialising parsed JSON will
 *                not match — key order and whitespace are part of what is signed.
 */
export function verifySvixSignature(
  secret: string,
  rawBody: string,
  headers: { id?: string; timestamp?: string; signature?: string },
  now: Date = new Date(),
): SvixResult {
  const { id, timestamp, signature } = headers;
  if (!id || !timestamp || !signature) return { ok: false, reason: "missing_headers" };

  const sent = Number(timestamp);
  if (!Number.isFinite(sent)) return { ok: false, reason: "bad_timestamp" };
  const drift = Math.abs(Math.floor(now.getTime() / 1000) - sent);
  if (drift > TIMESTAMP_TOLERANCE_SECONDS) return { ok: false, reason: "timestamp_out_of_tolerance" };

  const key = Buffer.from(secret.replace(/^whsec_/, ""), "base64");
  const expected = createHmac("sha256", key).update(`${id}.${timestamp}.${rawBody}`).digest("base64");

  // The header may carry several signatures while a secret is being rotated;
  // any one matching is a pass. Entries that are not v1 are skipped rather
  // than rejected, so a future version added alongside v1 does not break this.
  const candidates = signature
    .split(" ")
    .map((part) => part.trim())
    .filter((part) => part.startsWith("v1,"))
    .map((part) => part.slice(3));

  if (candidates.length === 0) return { ok: false, reason: "no_signatures" };
  // Every candidate is compared — no early return — so the time taken does not
  // depend on which position matched.
  let matched = false;
  for (const candidate of candidates) {
    if (safeEqual(candidate, expected)) matched = true;
  }
  return matched ? { ok: true } : { ok: false, reason: "no_match" };
}
