import { test } from "node:test";
import assert from "node:assert/strict";
import {
  LOGIN_CODE_LENGTH,
  LOGIN_CODE_MAX_ATTEMPTS,
  LOGIN_CODE_TTL_MS,
  generateLoginCode,
  hashesEqual,
  normalizeLoginCode,
  normalizeLoginEmail,
} from "./loginCode.js";

test("a generated code is exactly six digits, leading zeros preserved", () => {
  for (let i = 0; i < 500; i++) {
    const code = generateLoginCode();
    assert.match(code, /^\d{6}$/, `not six digits: ${code}`);
    assert.equal(code.length, LOGIN_CODE_LENGTH);
  }
});

// A code that silently dropped a leading zero would be five digits, which both
// shrinks the keyspace and fails the client's own length check.
test("low values keep their leading zeros rather than being shortened", () => {
  assert.equal(String(7).padStart(6, "0").length, 6);
  // Exercised through the generator by looking for any short output above.
  const codes = Array.from({ length: 2000 }, () => generateLoginCode());
  assert.ok(codes.every((c) => c.length === 6), "every code is six characters");
});

// Not a randomness test — it cannot be, at this sample size. It checks the one
// failure this code could plausibly have: `randomBytes % 1000000`, whose bias
// crowds output toward the low end of the range. A generator stuck in one
// region shows up as an empty bucket.
test("codes are spread across the keyspace, not crowded into the low range", () => {
  const buckets = new Array(10).fill(0);
  for (let i = 0; i < 5000; i++) {
    buckets[Math.floor(Number(generateLoginCode()) / 100_000)]++;
  }
  assert.ok(
    buckets.every((n) => n > 200),
    `some tenth of the range is starved, which is what modulo bias looks like: ${buckets.join(",")}`,
  );
});

test("codes are not repeated back to back", () => {
  const seen = new Set(Array.from({ length: 200 }, () => generateLoginCode()));
  assert.ok(seen.size > 190, `expected near-unique codes across 200 draws, got ${seen.size}`);
});

test("normalizeLoginCode accepts the formats people actually paste", () => {
  assert.equal(normalizeLoginCode("123456"), "123456");
  assert.equal(normalizeLoginCode("123 456"), "123456", "the spacing the email itself uses");
  assert.equal(normalizeLoginCode("123-456"), "123456");
  assert.equal(normalizeLoginCode("  123456  "), "123456", "phone keyboards add trailing spaces");
  assert.equal(normalizeLoginCode("000000"), "000000", "an all-zero code is a real code");
});

test("normalizeLoginCode rejects anything that is not exactly six digits", () => {
  for (const bad of ["12345", "1234567", "12345a", "abcdef", "", "   ", "12.3456", "١٢٣٤٥٦"]) {
    assert.equal(normalizeLoginCode(bad), null, `should reject ${JSON.stringify(bad)}`);
  }
});

test("normalizeLoginCode rejects non-strings rather than coercing them", () => {
  // A JSON body can carry anything. 123456 as a NUMBER must not be silently
  // accepted — the caller's own validation depends on the null.
  for (const bad of [123456, null, undefined, {}, [], true]) {
    assert.equal(normalizeLoginCode(bad as unknown), null);
  }
});

test("email normalisation matches between issuing and verifying", () => {
  assert.equal(normalizeLoginEmail("  Person@Example.COM "), "person@example.com");
  assert.equal(normalizeLoginEmail("person@example.com"), "person@example.com");
});

test("hashesEqual compares equal and unequal digests correctly", () => {
  const a = "a".repeat(64);
  const b = "b".repeat(64);
  assert.equal(hashesEqual(a, a), true);
  assert.equal(hashesEqual(a, b), false);
});

// timingSafeEqual throws on a length mismatch, which would turn a malformed
// stored value into a 500 instead of a rejected sign-in.
test("hashesEqual returns false on a length mismatch instead of throwing", () => {
  assert.doesNotThrow(() => hashesEqual("abc", "abcdef"));
  assert.equal(hashesEqual("abc", "abcdef"), false);
  assert.equal(hashesEqual("", "x"), false);
});

test("the safety constants stay within the range that makes a short code viable", () => {
  // These three numbers ARE the security argument in loginCode.ts. Widening any
  // of them silently is how a six-digit credential stops being one: at 100
  // attempts a million-value keyspace falls in an afternoon, and an hour-long
  // window leaves a live credential sitting in an inbox.
  assert.ok(LOGIN_CODE_MAX_ATTEMPTS <= 10, "attempt cap must stay tight");
  assert.ok(LOGIN_CODE_TTL_MS <= 15 * 60 * 1000, "a sign-in code must be short-lived");
  assert.ok(LOGIN_CODE_LENGTH >= 6, "shorter than six digits is not a credential");
});
