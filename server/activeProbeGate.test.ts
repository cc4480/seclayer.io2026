import { test } from "node:test";
import assert from "node:assert/strict";

process.env.DB_PATH = ":memory:";
// Ensure a clean baseline: neither bypass flag set for the first assertions.
delete process.env.DEV_SKIP_DOMAIN_VERIFICATION;
delete process.env.ALLOW_UNVERIFIED_ACTIVE_PROBES;

const { db } = await import("./db.js");
const { activeProbesUnlocked } = await import("./activeProbeGate.js");
const { config } = await import("./config.js");

test("blocked by default: an unverified domain does not unlock active probes", async () => {
  const u = (await db.getOrCreateUser(`gate-${Date.now()}@test.io`));
  assert.equal(await activeProbesUnlocked(u.id, "https://example.com/app"), false);
});

test("verified ownership unlocks active probes for that domain", async () => {
  const u = (await db.getOrCreateUser(`gate-verified-${Date.now()}@test.io`));
  // Start + mark a domain verified through the DB, the same path the DNS/file
  // verification flow uses.
  (await db.startDomainVerification(u.id, "myapp.example.com", "tok-abc123"));
  (await db.markDomainVerified(u.id, "myapp.example.com"));
  assert.equal(await activeProbesUnlocked(u.id, "https://myapp.example.com/login"), true);
  // A different, unverified domain for the same user is still blocked.
  assert.equal(await activeProbesUnlocked(u.id, "https://other.example.com/"), false);
});

test("the operator flag unlocks active probes for ANY target, regardless of verification", async () => {
  const u = (await db.getOrCreateUser(`gate-operator-${Date.now()}@test.io`));
  assert.equal(await activeProbesUnlocked(u.id, "https://anything.example.com/"), false, "blocked before the flag");

  const prev = config.allowUnverifiedActiveProbes;
  (config as any).allowUnverifiedActiveProbes = true;
  try {
    assert.equal(await activeProbesUnlocked(u.id, "https://anything.example.com/"), true, "operator flag unlocks everything");
  } finally {
    (config as any).allowUnverifiedActiveProbes = prev;
  }
});
