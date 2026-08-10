import { test } from "node:test";
import assert from "node:assert/strict";
import { PostgresDb } from "./pgDb.js";
import type { PgPool, PgResult, PgPoolClient } from "./pgClient.js";

// A mock pg pool that records every query (pool-level and client/transaction-
// level) and answers by first-substring match. Proves the adapter issues the
// right SQL ($n placeholders) + params, maps rows, and sequences transactions —
// all without a real Postgres.
class MockPg implements PgPool {
  poolCalls: Array<{ text: string; params: any[] }> = [];
  clientCalls: Array<{ text: string; params: any[] }> = [];
  released = 0;
  private responders: Array<{ match: string; res: PgResult }> = [];
  throwOn?: string;

  respond(match: string, rows: any[], rowCount = rows.length): this {
    this.responders.push({ match, res: { rows, rowCount } });
    return this;
  }
  private answer(text: string): PgResult {
    if (this.throwOn && text.includes(this.throwOn)) throw new Error("pg error: " + this.throwOn);
    for (const r of this.responders) if (text.includes(r.match)) return r.res;
    return { rows: [], rowCount: 0 };
  }
  async query(text: string, params: any[] = []): Promise<PgResult> {
    this.poolCalls.push({ text, params });
    return this.answer(text);
  }
  async connect(): Promise<PgPoolClient> {
    return {
      query: async (text: string, params: any[] = []) => {
        this.clientCalls.push({ text, params });
        return this.answer(text);
      },
      release: () => { this.released++; },
    };
  }
  async end(): Promise<void> {}
}

const USER_ROW = { id: "u1", email: "a@b.co", credits: 5, createdat: "2026-01-01T00:00:00Z", notifywebhook: null, emaildigest: 1, lastdigestat: null };

test("getUser: correct $n SQL + params, and pg-lowercase row maps to camelCase", async () => {
  const pg = new MockPg().respond("SELECT * FROM users WHERE id", [USER_ROW]);
  const db = new PostgresDb(pg);
  const user = await db.getUser("u1");
  assert.equal(pg.poolCalls[0].text, "SELECT * FROM users WHERE id = $1", "? -> $1");
  assert.deepEqual(pg.poolCalls[0].params, ["u1"]);
  assert.ok(user);
  assert.equal(user!.id, "u1");
  assert.equal(user!.createdAt, "2026-01-01T00:00:00Z", "createdat -> createdAt via normalizeRow");
  assert.equal(user!.emailDigest, true, "integer-boolean maps through");
});

test("createSession + getSessionUserId round-trip (auth path)", async () => {
  const pg = new MockPg();
  const db = new PostgresDb(pg);
  const raw = await db.createSession("u1");
  assert.match(pg.poolCalls[0].text, /INSERT INTO sessions .* VALUES \(\$1, \$2, \$3, \$4\)/);
  // The stored value is a hash of raw, never raw itself.
  assert.notEqual(pg.poolCalls[0].params[0], raw);

  // A valid, unexpired session resolves to its userId.
  pg.respond("SELECT * FROM sessions WHERE tokenHash", [{ tokenhash: "h", userid: "u1", expiresat: new Date(Date.now() + 60_000).toISOString() }]);
  assert.equal(await db.getSessionUserId(raw), "u1");
});

test("getOrCreateUser runs a real transaction: BEGIN, both INSERTs on the client, COMMIT", async () => {
  const pg = new MockPg()
    .respond("WHERE email", [])          // no existing user
    .respond("WHERE id", [USER_ROW]);    // the created user, read back
  const db = new PostgresDb(pg);
  const user = await db.getOrCreateUser("New@B.co");
  assert.ok(user);

  const clientSql = pg.clientCalls.map((c) => c.text);
  assert.equal(clientSql[0], "BEGIN");
  assert.match(clientSql[1], /INSERT INTO users/);
  assert.match(clientSql[2], /INSERT INTO transactions/);
  assert.equal(clientSql[3], "COMMIT");
  assert.equal(pg.released, 1, "the pooled client is always released");
  // Email is normalized before insert.
  assert.equal(pg.clientCalls[1].params[1], "new@b.co");
});

test("addCredits transaction updates users + api_keys + inserts a transaction row", async () => {
  const pg = new MockPg().respond("WHERE id", [USER_ROW]);
  const db = new PostgresDb(pg);
  await db.addCredits("u1", 10, "purchase", "sess_123");
  const clientSql = pg.clientCalls.map((c) => c.text);
  assert.equal(clientSql[0], "BEGIN");
  assert.match(clientSql[1], /UPDATE users SET credits/);
  assert.match(clientSql[2], /UPDATE api_keys SET credits/);
  assert.match(clientSql[3], /INSERT INTO transactions/);
  assert.equal(clientSql[4], "COMMIT");
});

test("a throw inside a transaction ROLLBACKs and releases the client", async () => {
  const pg = new MockPg().respond("WHERE id", [USER_ROW]);
  pg.throwOn = "UPDATE api_keys"; // fail mid-transaction
  const db = new PostgresDb(pg);
  await assert.rejects(db.addCredits("u1", 10, "purchase"), /pg error/);
  const clientSql = pg.clientCalls.map((c) => c.text);
  assert.ok(clientSql.includes("ROLLBACK"), "must ROLLBACK on error");
  assert.ok(!clientSql.includes("COMMIT"), "must not COMMIT a failed tx");
  assert.equal(pg.released, 1, "client released even on failure");
});

test("hasTransactionForSession: a row present -> true, no row -> false", async () => {
  const present = new PostgresDb(new MockPg().respond("SELECT 1 FROM transactions", [{ "?column?": 1 }]));
  assert.equal(await present.hasTransactionForSession("sess_x"), true);
  const absent = new PostgresDb(new MockPg()); // no responder -> empty rows
  assert.equal(await absent.hasTransactionForSession("sess_missing"), false);
});

test("healthy() reflects the pool: SELECT 1 ok -> true, error -> false", async () => {
  const okPg = new MockPg().respond("SELECT 1", [{ "?column?": 1 }]);
  assert.equal(await new PostgresDb(okPg).healthy(), true);
  const brokenPg = new MockPg();
  brokenPg.throwOn = "SELECT 1";
  assert.equal(await new PostgresDb(brokenPg).healthy(), false);
});
