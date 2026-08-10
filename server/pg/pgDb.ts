// Postgres adapter (in progress). Implements the same operations as
// server/db.ts's SqliteDb, but async and over a pg pool. It REUSES the exact
// SQL strings from SqliteDb, piped through toPositional (?->$n) and normalizeRow
// (lower-case pg keys -> camelCase), so the query logic is not re-derived and
// the existing row mappers work unchanged.
//
// STATUS: query infrastructure + the critical core (auth, users, credits,
// scans, api-key validation, health) are implemented and mock-tested. The
// remaining SqliteDb methods (monitors, suppressions, domains, nmap, oob,
// autofix) follow the IDENTICAL pattern shown here. The whole adapter must still
// be validated against a real Postgres (see server/pg/MIGRATION.md) before use —
// a mock can't surface pg's runtime type/NULL/transaction behavior.
import crypto from "crypto";
import type { User, Scan } from "../../src/types.js";
import { hashToken, maskKey } from "../dbCrypto.js";
import { rowToUser, rowToScan, rowToApiKey } from "../dbMappers.js";
import { toPositional } from "./pgParams.js";
import { normalizeRow, normalizeRows } from "./pgRowCase.js";
import type { PgPool, PgQueryable } from "./pgClient.js";

export class PostgresDb {
  constructor(private readonly pool: PgPool) {}

  // --- query helpers (mirror better-sqlite3's .get/.all/.run) --------------
  // `q` defaults to the pool; inside a transaction, callers pass the client so
  // the statement runs within the BEGIN/COMMIT.
  private async get(sql: string, params: any[] = [], q: PgQueryable = this.pool): Promise<any> {
    const { rows } = await q.query(toPositional(sql), params);
    return normalizeRow(rows[0]);
  }
  private async all(sql: string, params: any[] = [], q: PgQueryable = this.pool): Promise<any[]> {
    const { rows } = await q.query(toPositional(sql), params);
    return normalizeRows(rows);
  }
  private async run(sql: string, params: any[] = [], q: PgQueryable = this.pool): Promise<number> {
    const res = await q.query(toPositional(sql), params);
    return res.rowCount ?? 0;
  }
  // Async-native transaction: acquire a pooled client, BEGIN, run fn (which uses
  // that client via the `q` arg), COMMIT — or ROLLBACK on any throw. Because it's
  // async, composing methods (addCredits inside recoverStuckScans, etc.) is
  // natural, unlike better-sqlite3's synchronous-only transactions.
  private async tx<T>(fn: (q: PgQueryable) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const result = await fn(client);
      await client.query("COMMIT");
      return result;
    } catch (err) {
      try { await client.query("ROLLBACK"); } catch { /* ignore rollback failure */ }
      throw err;
    } finally {
      client.release();
    }
  }

  // --- Sessions + magic-link auth (SQL identical to SqliteDb) ---------------
  async createLoginToken(email: string, ttlMs = 15 * 60 * 1000): Promise<string> {
    const raw = crypto.randomBytes(32).toString("hex");
    const now = Date.now();
    await this.run(
      "INSERT INTO login_tokens (tokenHash, email, expiresAt, createdAt) VALUES (?, ?, ?, ?)",
      [hashToken(raw), email.toLowerCase().trim(), new Date(now + ttlMs).toISOString(), new Date(now).toISOString()],
    );
    return raw;
  }

  async consumeLoginToken(raw: string): Promise<string | null> {
    const hash = hashToken(raw);
    const row = await this.get("SELECT * FROM login_tokens WHERE tokenHash = ?", [hash]);
    if (!row || row.consumedAt) return null;
    if (new Date(row.expiresAt).getTime() < Date.now()) return null;
    await this.run("UPDATE login_tokens SET consumedAt = ? WHERE tokenHash = ?", [new Date().toISOString(), hash]);
    return row.email;
  }

  async createSession(userId: string, ttlMs = 30 * 24 * 60 * 60 * 1000): Promise<string> {
    const raw = crypto.randomBytes(32).toString("hex");
    const now = Date.now();
    await this.run(
      "INSERT INTO sessions (tokenHash, userId, expiresAt, createdAt) VALUES (?, ?, ?, ?)",
      [hashToken(raw), userId, new Date(now + ttlMs).toISOString(), new Date(now).toISOString()],
    );
    return raw;
  }

  async getSessionUserId(raw: string): Promise<string | null> {
    const row = await this.get("SELECT * FROM sessions WHERE tokenHash = ?", [hashToken(raw)]);
    if (!row) return null;
    if (new Date(row.expiresAt).getTime() < Date.now()) {
      await this.run("DELETE FROM sessions WHERE tokenHash = ?", [row.tokenHash]);
      return null;
    }
    return row.userId;
  }

  async deleteSession(raw: string): Promise<void> {
    await this.run("DELETE FROM sessions WHERE tokenHash = ?", [hashToken(raw)]);
  }

  // --- Users + credits ------------------------------------------------------
  async getUser(id: string): Promise<User | undefined> {
    return rowToUser(await this.get("SELECT * FROM users WHERE id = ?", [id]));
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    return rowToUser(await this.get("SELECT * FROM users WHERE email = ?", [email.toLowerCase().trim()]));
  }

  async getOrCreateUser(email: string): Promise<User> {
    const normEmail = email.toLowerCase().trim();
    const existing = await this.getUserByEmail(normEmail);
    if (existing) return existing;
    const id = "user_" + crypto.randomBytes(6).toString("hex");
    const now = new Date().toISOString();
    await this.tx(async (q) => {
      await this.run("INSERT INTO users (id, email, credits, createdAt) VALUES (?, ?, ?, ?)", [id, normEmail, 5, now], q);
      await this.run("INSERT INTO transactions (id, userId, amount, type, createdAt) VALUES (?, ?, ?, ?, ?)", ["tx-signup-" + id, id, 5, "purchase", now], q);
    });
    return (await this.getUser(id))!;
  }

  async addCredits(userId: string, amount: number, type: "purchase" | "scan_debit", stripeSessionId?: string): Promise<User> {
    const user = await this.getUser(userId);
    if (!user) throw new Error("User not found");
    const newCredits = Math.max(0, user.credits + amount);
    await this.tx(async (q) => {
      await this.run("UPDATE users SET credits = ? WHERE id = ?", [newCredits, userId], q);
      await this.run("UPDATE api_keys SET credits = ? WHERE userId = ? AND active = 1", [newCredits, userId], q);
      await this.run(
        "INSERT INTO transactions (id, userId, amount, type, stripeSessionId, createdAt) VALUES (?, ?, ?, ?, ?, ?)",
        ["tx_" + crypto.randomBytes(8).toString("hex"), userId, amount, type, stripeSessionId ?? null, new Date().toISOString()],
        q,
      );
    });
    return (await this.getUser(userId))!;
  }

  async deductCredits(userId: string, amount: number): Promise<boolean> {
    const user = await this.getUser(userId);
    if (!user || user.credits < amount) return false;
    await this.addCredits(userId, -amount, "scan_debit");
    return true;
  }

  async hasTransactionForSession(sessionId: string): Promise<boolean> {
    return !!(await this.get("SELECT 1 FROM transactions WHERE stripeSessionId = ? LIMIT 1", [sessionId]));
  }

  // --- Scans ----------------------------------------------------------------
  async createScan(userId: string, url: string, authHeader?: string): Promise<Scan> {
    const id = "scan_" + crypto.randomBytes(8).toString("hex");
    const now = new Date().toISOString();
    await this.run(
      "INSERT INTO scans (id, userId, url, authHeader, status, createdAt) VALUES (?, ?, ?, ?, ?, ?)",
      [id, userId, url, authHeader ?? null, "queued", now],
    );
    return (await this.getScan(id))!;
  }

  async getScan(id: string): Promise<Scan | undefined> {
    return rowToScan(await this.get("SELECT * FROM scans WHERE id = ?", [id]));
  }

  async listScans(userId: string): Promise<Scan[]> {
    const rows = await this.all("SELECT * FROM scans WHERE userId = ? ORDER BY createdAt DESC", [userId]);
    return rows.map((r) => rowToScan(r)!).filter(Boolean);
  }

  // --- API keys -------------------------------------------------------------
  async validateApiKey(apiKeyString: string): Promise<User | null> {
    const keyRow = await this.get("SELECT * FROM api_keys WHERE key = ?", [hashToken(apiKeyString)]);
    if (!keyRow || !keyRow.active) return null;
    return (await this.getUser(keyRow.userId)) ?? null;
  }

  async validateApiKeyAndDeduct(apiKeyString: string, quantity = 1): Promise<User | null> {
    const keyRow = await this.get("SELECT * FROM api_keys WHERE key = ?", [hashToken(apiKeyString)]);
    if (!keyRow || !keyRow.active) return null;
    const user = await this.getUser(keyRow.userId);
    if (!user || user.credits < quantity) return null;
    return this.addCredits(user.id, -quantity, "scan_debit");
  }

  // --- Health / lifecycle ---------------------------------------------------
  async healthy(): Promise<boolean> {
    try {
      await this.pool.query("SELECT 1");
      return true;
    } catch {
      return false;
    }
  }

  async close(): Promise<void> {
    try {
      await this.pool.end();
    } catch (err: any) {
      console.warn("[pgDb] Error while closing pool:", err?.message || err);
    }
  }

  // NOTE: unused imports (maskKey) are for the not-yet-ported generateApiKey/etc.
  // methods; referenced here to keep them in the module until those land.
  static readonly _pending = { maskKey };
}
