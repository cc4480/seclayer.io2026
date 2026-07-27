import { test } from "node:test";
import assert from "node:assert/strict";

process.env.DB_PATH = ":memory:";
process.env.FREE_MODE = "false";
// No RESEND_API_KEY → sendEmail logs to console and resolves, so the worker runs
// end-to-end here without any real email transport.
const { db } = await import("./db.js");
const { runDueDigests } = await import("./digestWorker.js");

test("mails an opted-in user with monitored targets and records the send time", async () => {
  const user = db.getOrCreateUser(`digest-${Date.now()}@test.io`);
  db.setEmailDigest(user.id, true);
  db.addMonitoredTarget(user.id, "https://93.184.216.34", 7);
  const s = db.createScan(user.id, "https://93.184.216.34");
  db.updateScan(s.id, { status: "complete", score: 70, severity: "medium", findings: [], completedAt: new Date().toISOString() });

  assert.equal(db.getUser(user.id)!.lastDigestAt, undefined);
  await runDueDigests(new Date());
  assert.ok(db.getUser(user.id)!.lastDigestAt, "lastDigestAt is set after a digest is sent");
});

test("skips a user who was mailed within the last 7 days", async () => {
  const user = db.getOrCreateUser(`digest-recent-${Date.now()}@test.io`);
  db.setEmailDigest(user.id, true);
  db.addMonitoredTarget(user.id, "https://1.1.1.1", 7);
  const twoDaysAgo = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString();
  db.markDigestSent(user.id, twoDaysAgo);

  await runDueDigests(new Date());
  assert.equal(db.getUser(user.id)!.lastDigestAt, twoDaysAgo, "recently-mailed user is not re-sent");
});

test("does not opt in users who never asked, and does not send with zero targets", async () => {
  const optedOut = db.getOrCreateUser(`digest-off-${Date.now()}@test.io`);
  db.addMonitoredTarget(optedOut.id, "https://8.8.8.8", 7); // has a target but never opted in

  const optedInNoTargets = db.getOrCreateUser(`digest-empty-${Date.now()}@test.io`);
  db.setEmailDigest(optedInNoTargets.id, true); // opted in, but no monitors

  await runDueDigests(new Date());
  assert.equal(db.getUser(optedOut.id)!.lastDigestAt, undefined, "opted-out user is never mailed");
  assert.equal(db.getUser(optedInNoTargets.id)!.lastDigestAt, undefined, "no email with zero targets");
});
