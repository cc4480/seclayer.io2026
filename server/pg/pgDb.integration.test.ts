// Real-Postgres integration test for the adapter. Runs ONLY when DATABASE_URL
// is set (so the normal suite on SQLite is unaffected); apply server/pg/schema.sql
// to that database first. Exercises the full adapter breadth against a live
// Postgres and cleans up every row it creates.
import { test } from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { PostgresDb } from "./pgDb.js";
import type { PgPool } from "./pgClient.js";

const DATABASE_URL = process.env.DATABASE_URL;

test("PostgresDb: full adapter breadth against a real Postgres", { skip: !DATABASE_URL }, async () => {
  const pool = new pg.Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
  const db = new PostgresDb(pool as unknown as PgPool);
  const email = `pgint+${Date.now()}@seclayer.test`;
  let userId = "";
  try {
    // Users + credits (transactions)
    const u = await db.getOrCreateUser(email);
    userId = u.id;
    assert.equal(u.credits, 5);
    assert.ok(u.createdAt, "camelCase createdAt survives pg lowercasing");
    assert.equal(u.emailDigest, false);
    assert.equal((await db.getOrCreateUser(email)).id, u.id, "idempotent");
    assert.equal((await db.addCredits(u.id, 10, "purchase", "sess_" + Date.now())).credits, 15);
    assert.equal(await db.deductCredits(u.id, 1), true);
    assert.equal((await db.getUser(u.id))!.credits, 14);
    assert.ok((await db.listTransactions(u.id)).length >= 2);

    // User settings
    assert.equal((await db.setUserWebhook(u.id, "https://hook.test"))!.notifyWebhook, "https://hook.test");
    assert.equal((await db.setEmailDigest(u.id, true))!.emailDigest, true);
    assert.ok((await db.listDigestRecipients()).some((r) => r.id === u.id));
    await db.setUserDeepseekKey(u.id, "  sk-abc  ");
    assert.equal(await db.getUserDeepseekKey(u.id), "sk-abc", "trimmed BYOK key");

    // Scans: create -> update (JSON round-trip) -> share token -> previous/latest
    const scan = await db.createScan(u.id, "https://example.test");
    assert.equal(scan.status, "queued");
    const findings = [{ id: "f1", title: "X", severity: "high", confidence: "high", category: "RED_TEAM", description: "d", fix: "f" } as any];
    const updated = await db.updateScan(scan.id, { status: "complete", score: 42, severity: "high", findings, completedAt: new Date().toISOString() });
    assert.equal(updated.status, "complete");
    assert.equal(updated.score, 42);
    assert.deepEqual(updated.findings?.map((f: any) => f.title), ["X"], "findings JSON round-trips through text column");
    const share = await db.createShareToken(u.id, scan.id);
    assert.ok(share && share.startsWith("shr_"));
    assert.equal((await db.getScanByShareToken(share!))!.id, scan.id);
    assert.equal(await db.createShareToken(u.id, scan.id), share, "share token is idempotent");
    assert.equal(await db.revokeShareToken(u.id, scan.id), true);
    assert.equal(await db.getScanByShareToken(share!), undefined, "revoked token no longer resolves");
    assert.ok((await db.listScans(u.id)).length >= 1);

    // cancelScan refunds a credit IN THE SAME TRANSACTION (a fresh queued scan).
    const before = (await db.getUser(u.id))!.credits;
    const q2 = await db.createScan(u.id, "https://cancel.test");
    const canceled = await db.cancelScan(u.id, q2.id);
    assert.equal(canceled!.status, "canceled");
    assert.equal((await db.getUser(u.id))!.credits, before + 1, "credit refunded atomically on cancel");

    // recoverStuckScans: a queued scan is failed + refunded on recovery.
    const stuck = await db.createScan(u.id, "https://stuck.test");
    const creditsBeforeRecover = (await db.getUser(u.id))!.credits;
    const recovered = await db.recoverStuckScans();
    assert.ok(recovered >= 1);
    assert.equal((await db.getScan(stuck.id))!.status, "failed");
    assert.ok((await db.getUser(u.id))!.credits >= creditsBeforeRecover + 1);

    // API keys
    const { apiKey, rawKey } = await db.generateApiKey(u.id);
    assert.ok(rawKey.startsWith("sl_live_"));
    assert.equal((await db.validateApiKey(rawKey))!.id, u.id);
    assert.ok((await db.listApiKeys(u.id)).some((k) => k.id === apiKey.id));
    assert.equal(await db.revokeApiKey(u.id, apiKey.id), true);
    assert.equal(await db.validateApiKey(rawKey), null, "revoked key rejected");

    // Domain verification
    await db.startDomainVerification(u.id, "example.test", "vtok");
    assert.equal(await db.isDomainVerified(u.id, "example.test"), false);
    await db.markDomainVerified(u.id, "example.test", "dns");
    assert.equal(await db.isDomainVerified(u.id, "example.test"), true);

    // Suppressions + read-model
    await db.addSuppression(u.id, "https://example.test", "X", "false positive");
    const withSupp = await db.getScanWithSuppressedFindings(updated);
    assert.equal(withSupp.findings?.find((f: any) => f.title === "X")?.isFalsePositive, true);

    // Monitored targets (schedule)
    const mon = await db.addMonitoredTarget(u.id, "https://mon.test", { frequencyDays: 1, hour: 9, minute: 0 });
    assert.ok(mon.id);
    assert.equal(await db.setMonitoredPaused(u.id, mon.id, true), true);
    assert.equal(await db.removeMonitoredTarget(u.id, mon.id), true);

    // Nmap
    const nmap = await db.createNmapScan(u.id, "https://nmap.test");
    assert.equal(nmap.status, "queued");
    assert.equal(await db.hasInFlightNmapScan(u.id), true);
    await db.updateNmapScan(nmap.id, { status: "complete", resolvedIp: "1.2.3.4", completedAt: new Date().toISOString() });
    assert.equal((await db.getNmapScan(nmap.id))!.status, "complete");

    // Autofix
    const afx = await db.createAutofixSession(u.id, "https://x.test", "T", "RED_TEAM");
    assert.equal((await db.incrementAutofixTurn(afx.id)).turns, 1);
    assert.equal((await db.completeAutofixSession(afx.id, "done")).status, "done");

    // OOB
    await db.registerOobToken("oobtok_" + userId);
    assert.equal(await db.recordOobEvent("oobtok_" + userId, { method: "GET", sourceIp: "9.9.9.9", path: "/x" }), true);
    assert.ok((await db.getOobEvents("oobtok_" + userId)).length >= 1);

    assert.equal(await db.healthy(), true);
  } finally {
    // Clean up everything this test created.
    for (const t of ["sessions", "scans", "transactions", "api_keys", "domain_verifications", "suppressions", "monitored_targets", "nmap_scans", "autofix_sessions"]) {
      await pool.query(`DELETE FROM ${t} WHERE userId = $1`, [userId]).catch(() => {});
    }
    await pool.query("DELETE FROM oob_events WHERE token = $1", ["oobtok_" + userId]).catch(() => {});
    await pool.query("DELETE FROM oob_tokens WHERE token = $1", ["oobtok_" + userId]).catch(() => {});
    await pool.query("DELETE FROM users WHERE id = $1", [userId]).catch(() => {});
    await pool.end().catch(() => {});
  }
});

// Proves the SELECT ... FOR UPDATE atomicity of deductCredits on a real Postgres:
// concurrent debits sharing one credit must serialize so exactly one wins (no
// double-spend, balance never negative). The SQLite path has an equivalent test
// in server/routes/scans.test.ts; this asserts the production backend directly.
test("PostgresDb: concurrent deductCredits never double-spends the last credit", { skip: !DATABASE_URL }, async () => {
  const pool = new pg.Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
  const db = new PostgresDb(pool as unknown as PgPool);
  const email = `pgconc+${Date.now()}@seclayer.test`;
  let userId = "";
  try {
    const u = await db.getOrCreateUser(email);
    userId = u.id;
    await db.deductCredits(u.id, u.credits - 1); // drain to exactly 1
    assert.equal((await db.getUser(u.id))!.credits, 1);

    const results = await Promise.all(Array.from({ length: 8 }, () => db.deductCredits(u.id, 1)));
    assert.equal(results.filter(Boolean).length, 1, "exactly one concurrent debit may succeed");
    assert.equal((await db.getUser(u.id))!.credits, 0, "balance must never go negative");
  } finally {
    await pool.query("DELETE FROM transactions WHERE userId = $1", [userId]).catch(() => {});
    await pool.query("DELETE FROM api_keys WHERE userId = $1", [userId]).catch(() => {});
    await pool.query("DELETE FROM users WHERE id = $1", [userId]).catch(() => {});
    await pool.end().catch(() => {});
  }
});
