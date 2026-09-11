/**
 * One-time sign-in codes.
 *
 * These replace the emailed magic link. The link had a real operational
 * problem — mail security scanners and link prefetchers fetch every URL in a
 * message automatically, which is why routes/auth.ts had to split "check the
 * token" from "spend the token" — and it only ever worked if the mail was
 * opened on the same device as the browser waiting to be signed in.
 *
 * THE IMPORTANT DIFFERENCE FROM A TOKEN. Everywhere else in this codebase a
 * single-use secret is 32 bytes of CSPRNG output, and dbCrypto.hashToken's
 * plain unsalted SHA-256 is correct for it precisely because there is nothing
 * guessable to grind against. A six-digit code is the opposite: the entire
 * keyspace is a million values, small enough to walk in seconds. Three
 * properties, all enforced below and in the two verifyLoginCode
 * implementations, are what make it safe anyway:
 *
 *  1. LOOKUP IS SCOPED TO THE EMAIL. A code is never looked up by its hash
 *     alone. If it were, an attacker could submit guesses unattached to any
 *     address and a hit would sign them in as whoever happened to hold that
 *     code — turning a 1-in-a-million guess against ONE account into a
 *     1-in-a-million guess against EVERY live code at once. Scoping to the
 *     address means a guess is aimed at one named target.
 *  2. ATTEMPTS ARE CAPPED. Five wrong guesses kill the code. A million-value
 *     keyspace with unlimited tries is not a secret; with five tries it is
 *     a 1-in-200,000 shot before the credential is destroyed.
 *  3. ONLY ONE CODE IS LIVE PER ADDRESS. Issuing a new code retires the
 *     previous one. Otherwise requesting N codes would leave N live values and
 *     divide the guessing odds by N.
 *
 * Change any of the three and the code stops being a credential.
 */

import crypto from "crypto";

export const LOGIN_CODE_LENGTH = 6;

// Short, because a live code is a credential sitting in an inbox. Long enough
// to survive fetching the mail on a phone and typing it on a laptop, which is
// the case the magic link handled badly.
export const LOGIN_CODE_TTL_MS = 10 * 60 * 1000;

// See property 2 above. Counts wrong guesses against one issued code, not
// requests — a user who mistypes twice and then gets it right is unaffected.
export const LOGIN_CODE_MAX_ATTEMPTS = 5;

/**
 * A uniformly random six-digit code, leading zeros preserved.
 *
 * crypto.randomInt, not `randomBytes % 1000000`: the modulo of a byte-derived
 * integer is biased toward the low end of the range, which shrinks the real
 * keyspace of a secret that has little to spare.
 */
export function generateLoginCode(): string {
  return String(crypto.randomInt(0, 10 ** LOGIN_CODE_LENGTH)).padStart(LOGIN_CODE_LENGTH, "0");
}

/**
 * Canonicalise what the user actually typed, or null if it cannot be a code.
 *
 * People paste "123 456" and "123-456" because that is how codes are formatted
 * in mail, and phone keyboards add trailing spaces. Stripping separators is not
 * leniency about the secret — the digits must still be exactly right — it just
 * avoids rejecting a correct code for its punctuation and burning one of the
 * five attempts on a formatting difference.
 */
export function normalizeLoginCode(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const digits = raw.replace(/[\s-]/g, "");
  return new RegExp(`^\\d{${LOGIN_CODE_LENGTH}}$`).test(digits) ? digits : null;
}

/** Normalised mailbox identity. One place, so issuing and verifying agree. */
export function normalizeLoginEmail(raw: string): string {
  return raw.toLowerCase().trim();
}

/**
 * Why a verification failed.
 *
 * Callers must NOT surface these apart: telling "wrong code" from "no code was
 * ever issued for that address" turns the endpoint into a way to test which
 * addresses have accounts, and telling "expired" from "wrong" tells an attacker
 * whether a guess was ever close. The reasons exist for logs and for deciding
 * whether to invite a retry, not for the response body.
 */
export type LoginCodeFailure = "invalid" | "expired" | "too_many_attempts";

export type LoginCodeResult =
  | { ok: true; email: string }
  | { ok: false; reason: LoginCodeFailure };

/**
 * Constant-time comparison of two hex digests.
 *
 * The database comparison is already an equality test on a hash, so the timing
 * signal here is slight — but this runs once per guess against a credential
 * with a million-value keyspace, and a length-independent compare costs
 * nothing. timingSafeEqual throws on a length mismatch, hence the guard.
 */
export function hashesEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}
