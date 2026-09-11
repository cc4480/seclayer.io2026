import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { suppressionForEvent } from "./emailSuppression.js";
import { verifySvixSignature, TIMESTAMP_TOLERANCE_SECONDS } from "./svixSignature.js";
import { db } from "./db.js";
import { sendEmail } from "./email.js";

// ── Which events stop which mail ────────────────────────────────────────────
// Every mistake in this table is silent: nobody notices an ignored bounce until
// reputation has already slipped, and nobody notices a complaint suppressing
// the wrong thing until somebody cannot log in.

test("a hard bounce suppresses ALL mail — the address does not exist", () => {
  const d = suppressionForEvent("email.bounced", {
    to: "gone@test.io",
    bounce: { type: "Permanent", subType: "NoEmail", message: "no such mailbox" },
  });
  assert.deepEqual(d, { email: "gone@test.io", scope: "all", reason: "hard_bounce", detail: "no such mailbox" });
});

// THE one to get right. A soft bounce is a full mailbox or a transient server
// problem; it clears by itself, and suppressing on one would quietly cut off a
// real user whose inbox was briefly over quota.
test("a soft bounce suppresses nothing", () => {
  assert.equal(
    suppressionForEvent("email.bounced", { to: "full@test.io", bounce: { type: "Transient", subType: "MailboxFull" } }),
    null,
  );
});

test("a complaint suppresses BULK only", () => {
  const d = suppressionForEvent("email.complained", { to: "cross@test.io" });
  assert.equal(d?.scope, "bulk");
  assert.equal(d?.reason, "complaint");
});

test("events that say nothing about deliverability are ignored", () => {
  for (const t of ["email.sent", "email.delivered", "email.opened", "email.clicked", "email.delivery_delayed"]) {
    assert.equal(suppressionForEvent(t, { to: "a@b.co" }), null, t);
  }
});

test("the recipient is read whether Resend sends a string or an array", () => {
  assert.equal(suppressionForEvent("email.complained", { to: ["arr@test.io"] })?.email, "arr@test.io");
  assert.equal(suppressionForEvent("email.complained", { to: "str@test.io" })?.email, "str@test.io");
});

test("a payload with no recipient returns null rather than throwing", () => {
  assert.equal(suppressionForEvent("email.bounced", {}), null);
  assert.equal(suppressionForEvent("email.bounced", { to: [] }), null);
});

// ── The stored list ─────────────────────────────────────────────────────────

test("a hard-bounced address blocks every kind of mail", async () => {
  await db.suppressEmail("s1@test.io", "all", "hard_bounce");
  assert.equal(await db.isEmailSuppressed("s1@test.io", "bulk"), true);
  assert.equal(await db.isEmailSuppressed("s1@test.io", "account"), true);
});

// The decision that keeps a digest complaint from locking someone out.
test("a complaint blocks bulk but NOT account mail", async () => {
  await db.suppressEmail("s2@test.io", "bulk", "complaint");
  assert.equal(await db.isEmailSuppressed("s2@test.io", "bulk"), true);
  assert.equal(await db.isEmailSuppressed("s2@test.io", "account"), false);
});

test("an address that was never suppressed is not blocked", async () => {
  assert.equal(await db.isEmailSuppressed("never@test.io", "bulk"), false);
});

test("matching ignores case and surrounding whitespace", async () => {
  await db.suppressEmail("  Mixed@Test.IO ", "all", "hard_bounce");
  assert.equal(await db.isEmailSuppressed("mixed@test.io", "account"), true);
});

test("a repeated webhook upserts rather than failing on the primary key", async () => {
  await db.suppressEmail("s3@test.io", "bulk", "complaint");
  await db.suppressEmail("s3@test.io", "bulk", "complaint");
  assert.equal(await db.isEmailSuppressed("s3@test.io", "bulk"), true);
});

// Someone who complained AND whose mailbox was then deleted is both; the
// stricter rule is the true one. Widening back to bulk-only would resume
// mailing an address that does not exist.
test("an existing 'all' is never downgraded to 'bulk'", async () => {
  await db.suppressEmail("s4@test.io", "all", "hard_bounce");
  await db.suppressEmail("s4@test.io", "bulk", "complaint");
  assert.equal(await db.isEmailSuppressed("s4@test.io", "account"), true);
});

test("a 'bulk' IS upgraded to 'all' when the address later hard-bounces", async () => {
  await db.suppressEmail("s5@test.io", "bulk", "complaint");
  await db.suppressEmail("s5@test.io", "all", "hard_bounce");
  assert.equal(await db.isEmailSuppressed("s5@test.io", "account"), true);
});

test("an empty address is ignored rather than stored as a blank row", async () => {
  await db.suppressEmail("   ", "all", "hard_bounce");
  assert.equal(await db.isEmailSuppressed("", "account"), false);
});

test("unsuppressing lets the address receive mail again", async () => {
  await db.suppressEmail("s6@test.io", "all", "hard_bounce");
  await db.unsuppressEmail("s6@test.io");
  assert.equal(await db.isEmailSuppressed("s6@test.io", "account"), false);
});

// ── Webhook signature ───────────────────────────────────────────────────────
// This guards the endpoint that writes the list above. Unverified, anyone who
// found the URL could forge a bounce for any address and permanently stop that
// person receiving sign-in codes.

const SECRET = `whsec_${Buffer.from("seclayer-test-signing-key").toString("base64")}`;
const BODY = JSON.stringify({ type: "email.bounced", data: { to: "a@b.co" } });

function headersAt(when: Date, body = BODY, secret = SECRET, id = "msg_1") {
  const ts = String(Math.floor(when.getTime() / 1000));
  const key = Buffer.from(secret.replace(/^whsec_/, ""), "base64");
  const sig = createHmac("sha256", key).update(`${id}.${ts}.${body}`).digest("base64");
  return { id, timestamp: ts, signature: `v1,${sig}` };
}

const NOW = new Date("2026-09-11T12:00:00Z");

test("a correctly signed payload verifies", () => {
  assert.deepEqual(verifySvixSignature(SECRET, BODY, headersAt(NOW), NOW), { ok: true });
});

test("a signature made with the wrong secret is rejected", () => {
  assert.equal(verifySvixSignature(SECRET, BODY, headersAt(NOW, BODY, "whsec_d3Jvbmc="), NOW).ok, false);
});

test("a body altered after signing is rejected", () => {
  const tampered = JSON.stringify({ type: "email.bounced", data: { to: "victim@test.io" } });
  assert.equal(verifySvixSignature(SECRET, tampered, headersAt(NOW), NOW).ok, false);
});

// Replay: without a timestamp bound, a captured request stays valid forever and
// can re-suppress an address the user has since fixed.
test("a stale payload outside the tolerance window is rejected", () => {
  const old = new Date(NOW.getTime() - (TIMESTAMP_TOLERANCE_SECONDS + 60) * 1000);
  const r = verifySvixSignature(SECRET, BODY, headersAt(old), NOW);
  assert.equal(r.ok, false);
  assert.equal(r.ok === false && r.reason, "timestamp_out_of_tolerance");
});

test("ordinary clock drift inside the window is allowed", () => {
  const skewed = new Date(NOW.getTime() - (TIMESTAMP_TOLERANCE_SECONDS - 30) * 1000);
  assert.equal(verifySvixSignature(SECRET, BODY, headersAt(skewed), NOW).ok, true);
});

test("missing headers are rejected rather than throwing", () => {
  assert.equal(verifySvixSignature(SECRET, BODY, {}, NOW).ok, false);
  assert.equal(verifySvixSignature(SECRET, BODY, { id: "x" }, NOW).ok, false);
});

test("one of several rotated signatures matching is enough", () => {
  const h = headersAt(NOW);
  const other = headersAt(NOW, BODY, "whsec_b3RoZXI=");
  assert.equal(
    verifySvixSignature(SECRET, BODY, { ...h, signature: `${other.signature} ${h.signature}` }, NOW).ok,
    true,
  );
});

// ── What sendEmail does about it ────────────────────────────────────────────

// Caught in testing: the route answered "your sign-in code is on its way" with
// a 200 while the message was silently dropped, stranding the user at a prompt
// they could never satisfy. Account mail to a hard-bounced address must fail
// LOUDLY so the caller can say so.
test("account mail to a hard-bounced address throws rather than silently vanishing", async () => {
  await db.suppressEmail("loud@test.io", "all", "hard_bounce");
  await assert.rejects(
    () => sendEmail({ to: "loud@test.io", subject: "Your code", html: "<p>123456</p>" }),
    /suppression list/,
  );
});

// A digest that is not sent is the intended outcome, and the caller has nothing
// useful to do about it — so this one stays quiet.
test("bulk mail to a suppressed address is skipped quietly", async () => {
  await db.suppressEmail("quiet@test.io", "all", "hard_bounce");
  await sendEmail({ to: "quiet@test.io", subject: "Digest", html: "<p>hi</p>", kind: "bulk" });
});

// A complaint must never block a sign-in code: the recipient's own action just
// asked for it, and suppressing it would lock them out over a digest.
test("account mail still sends to an address that only complained", async () => {
  await db.suppressEmail("complained@test.io", "bulk", "complaint");
  await sendEmail({ to: "complained@test.io", subject: "Your code", html: "<p>123456</p>" });
});
