import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { verifySvixSignature, TIMESTAMP_TOLERANCE_SECONDS } from "./svixSignature.js";

// A real (throwaway) endpoint secret in Resend's `whsec_<base64>` shape.
const SECRET = "whsec_" + Buffer.from("seclayer-test-signing-key-0123456789").toString("base64");
const NOW = new Date("2026-09-14T12:00:00Z");
const TS = String(Math.floor(NOW.getTime() / 1000));
const ID = "msg_2abcDEF";
const BODY = '{"type":"email.bounced","data":{"to":["x@y.test"]}}';

// Sign exactly the way the scheme specifies: `${id}.${timestamp}.${rawBody}`,
// HMAC-SHA256 with the base64-decoded secret, base64-encoded.
function sign(body = BODY, id = ID, ts = TS, secret = SECRET): string {
  const key = Buffer.from(secret.replace(/^whsec_/, ""), "base64");
  return createHmac("sha256", key).update(`${id}.${ts}.${body}`).digest("base64");
}

test("verifySvixSignature accepts a correctly signed webhook", () => {
  const res = verifySvixSignature(SECRET, BODY, { id: ID, timestamp: TS, signature: `v1,${sign()}` }, NOW);
  assert.deepEqual(res, { ok: true });
});

test("verifySvixSignature rejects a forged signature — the whole point of the guard", () => {
  const forged = Buffer.from("not-the-real-signature-at-all").toString("base64");
  const res = verifySvixSignature(SECRET, BODY, { id: ID, timestamp: TS, signature: `v1,${forged}` }, NOW);
  assert.deepEqual(res, { ok: false, reason: "no_match" });
});

test("verifySvixSignature rejects a body tampered with after signing", () => {
  const sig = sign(); // signed over BODY
  const tampered = '{"type":"email.bounced","data":{"to":["victim@elsewhere.test"]}}';
  const res = verifySvixSignature(SECRET, tampered, { id: ID, timestamp: TS, signature: `v1,${sig}` }, NOW);
  assert.deepEqual(res, { ok: false, reason: "no_match" });
});

test("verifySvixSignature rejects a signature made with a different secret", () => {
  const otherSecret = "whsec_" + Buffer.from("a-completely-different-signing-key").toString("base64");
  const res = verifySvixSignature(
    SECRET, BODY, { id: ID, timestamp: TS, signature: `v1,${sign(BODY, ID, TS, otherSecret)}` }, NOW);
  assert.deepEqual(res, { ok: false, reason: "no_match" });
});

test("verifySvixSignature requires all three headers", () => {
  const sig = `v1,${sign()}`;
  assert.deepEqual(verifySvixSignature(SECRET, BODY, { timestamp: TS, signature: sig }, NOW), { ok: false, reason: "missing_headers" });
  assert.deepEqual(verifySvixSignature(SECRET, BODY, { id: ID, signature: sig }, NOW), { ok: false, reason: "missing_headers" });
  assert.deepEqual(verifySvixSignature(SECRET, BODY, { id: ID, timestamp: TS }, NOW), { ok: false, reason: "missing_headers" });
});

test("verifySvixSignature rejects a non-numeric timestamp", () => {
  const res = verifySvixSignature(SECRET, BODY, { id: ID, timestamp: "not-a-number", signature: `v1,${sign()}` }, NOW);
  assert.deepEqual(res, { ok: false, reason: "bad_timestamp" });
});

test("verifySvixSignature refuses a replay outside the tolerance window, both directions", () => {
  const stale = String(Number(TS) - TIMESTAMP_TOLERANCE_SECONDS - 1);
  const future = String(Number(TS) + TIMESTAMP_TOLERANCE_SECONDS + 1);
  assert.deepEqual(
    verifySvixSignature(SECRET, BODY, { id: ID, timestamp: stale, signature: `v1,${sign(BODY, ID, stale)}` }, NOW),
    { ok: false, reason: "timestamp_out_of_tolerance" });
  assert.deepEqual(
    verifySvixSignature(SECRET, BODY, { id: ID, timestamp: future, signature: `v1,${sign(BODY, ID, future)}` }, NOW),
    { ok: false, reason: "timestamp_out_of_tolerance" });
});

test("verifySvixSignature still accepts a timestamp at the edge of tolerance (clock drift)", () => {
  const edge = String(Number(TS) - TIMESTAMP_TOLERANCE_SECONDS);
  const res = verifySvixSignature(SECRET, BODY, { id: ID, timestamp: edge, signature: `v1,${sign(BODY, ID, edge)}` }, NOW);
  assert.deepEqual(res, { ok: true });
});

test("verifySvixSignature accepts any one of several signatures during a secret rotation", () => {
  const otherSecret = "whsec_" + Buffer.from("the-previous-rotating-signing-key").toString("base64");
  const header = `v1,${sign(BODY, ID, TS, otherSecret)} v1,${sign()}`; // old one first, current second
  assert.deepEqual(verifySvixSignature(SECRET, BODY, { id: ID, timestamp: TS, signature: header }, NOW), { ok: true });
});

test("verifySvixSignature skips unknown scheme versions but still honours a v1 match", () => {
  const header = `v2,something-from-the-future v1,${sign()}`;
  assert.deepEqual(verifySvixSignature(SECRET, BODY, { id: ID, timestamp: TS, signature: header }, NOW), { ok: true });
});

test("verifySvixSignature reports no_signatures when the header carries no v1 entry", () => {
  const res = verifySvixSignature(SECRET, BODY, { id: ID, timestamp: TS, signature: "v2,only-a-future-version" }, NOW);
  assert.deepEqual(res, { ok: false, reason: "no_signatures" });
});

test("verifySvixSignature binds the signature to the message id", () => {
  // Signature computed for a DIFFERENT svix-id must not verify — otherwise one
  // captured signature could be replayed under a fresh id.
  const res = verifySvixSignature(
    SECRET, BODY, { id: "msg_someOtherId", timestamp: TS, signature: `v1,${sign()}` }, NOW);
  assert.deepEqual(res, { ok: false, reason: "no_match" });
});
