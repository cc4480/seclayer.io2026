// Postgres adapter. Implements the same operations as server/db.ts's SqliteDb,
// but async and over a pg pool. It REUSES the exact SQL strings from SqliteDb,
// piped through toPositional (?->$n) and normalizeRow (lower-case pg keys ->
// camelCase), so the query logic is not re-derived and the existing row mappers
// (server/dbMappers.ts) work unchanged.
//
// Validated against a real Postgres (Supabase) — see server/pg/pgDb.integration.test.ts.
import crypto from "crypto";
import type {
  User, Scan, CreditTransaction, ApiKey, Finding, SuppressionRule, MonitoredTarget,
  DomainVerification, OobEvent, NmapScan, AutofixSession,
} from "../../src/types.js";
import { hashToken, maskKey, sealSecret, openSecret } from "../dbCrypto.js";
import {
  rowToUser, rowToScan, rowToApiKey, rowToDomainVerification, rowToMonitoredTarget,
  rowToNmapScan, rowToAutofixSession,
} from "../dbMappers.js";
import { scoreFindings } from "../scoring.js";
import { MonitorSchedule, computeNextRun, describeSchedule } from "../schedule.js";
import { cleanUrl } from "../urlClean.js";
import { toPositional } from "./pgParams.js";
import { normalizeRow, normalizeRows } from "./pgRowCase.js";
import type { PgPool, PgQueryable } from "./pgClient.js";
// Type-only import (erased at runtime), so this does NOT pull server/db.js in —
// which would instantiate SqliteDb and open the SQLite file. It only makes tsc
// verify this adapter satisfies the same contract SqliteDb defines.
import { STALE_LEASE_MS } from "../db.js";
import type { Db } from "../db.js";

export class PostgresDb implements Db {
  constructor(private readonly pool: PgPool) {}

  // --- query helpers (mirror better-sqlite3's .get/.all/.run) ---------------
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
  // Async-native transaction: acquire a client, BEGIN, run fn (which uses that
  // client via `q`), COMMIT — or ROLLBACK on any throw. Because it's async,
  // composing methods (credit refund inside recoverStuckScans, etc.) is natural.
  private async tx<T>(fn: (q: PgQueryable) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const result = await fn(client);
      await client.query("COMMIT");
      return result;
    } catch (err) {
      try { await client.query("ROLLBACK"); } catch { /* ignore */ }
      throw err;
    } finally {
      client.release();
    }
  }

  // Credit adjustment that runs on a CALLER-SUPPLIED queryable, so it can be
  // composed inside another transaction (recoverStuckScans/cancelScan refund a
  // credit atomically with the status change). Public addCredits wraps it in its
  // own transaction. Mirrors SqliteDb.addCredits' body exactly.
  private async _addCreditsWithin(q: PgQueryable, userId: string, amount: number, type: "purchase" | "scan_debit", stripeSessionId?: string): Promise<void> {
    const user = rowToUser(await this.get("SELECT * FROM users WHERE id = ?", [userId], q));
    if (!user) throw new Error("User not found");
    const newCredits = Math.max(0, user.credits + amount);
    await this.run("UPDATE users SET credits = ? WHERE id = ?", [newCredits, userId], q);
    await this.run("UPDATE api_keys SET credits = ? WHERE userId = ? AND active = 1", [newCredits, userId], q);
    await this.run(
      "INSERT INTO transactions (id, userId, amount, type, stripeSessionId, createdAt) VALUES (?, ?, ?, ?, ?, ?)",
      ["tx_" + crypto.randomBytes(8).toString("hex"), userId, amount, type, stripeSessionId ?? null, new Date().toISOString()],
      q,
    );
  }

  // --- Magic-link auth + sessions -------------------------------------------
  async createLoginToken(email: string, ttlMs = 15 * 60 * 1000): Promise<string> {
    const raw = crypto.randomBytes(32).toString("hex");
    const now = Date.now();
    await this.run("INSERT INTO login_tokens (tokenHash, email, expiresAt, createdAt) VALUES (?, ?, ?, ?)",
      [hashToken(raw), email.toLowerCase().trim(), new Date(now + ttlMs).toISOString(), new Date(now).toISOString()]);
    return raw;
  }
  // Validates a magic-link token without burning it — see db.ts's peekLoginToken
  // for why the single use must not be spent on the GET.
  async peekLoginToken(raw: string): Promise<string | null> {
    const row = await this.get("SELECT * FROM login_tokens WHERE tokenHash = ?", [hashToken(raw)]);
    if (!row || row.consumedAt) return null;
    if (new Date(row.expiresAt).getTime() < Date.now()) return null;
    return row.email;
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
    await this.run("INSERT INTO sessions (tokenHash, userId, expiresAt, createdAt) VALUES (?, ?, ?, ?)",
      [hashToken(raw), userId, new Date(now + ttlMs).toISOString(), new Date(now).toISOString()]);
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

  // --- User settings --------------------------------------------------------
  async setUserWebhook(userId: string, url: string | null): Promise<User | undefined> {
    await this.run("UPDATE users SET notifyWebhook = ? WHERE id = ?", [url, userId]);
    return this.getUser(userId);
  }
  async setEmailDigest(userId: string, enabled: boolean): Promise<User | undefined> {
    await this.run("UPDATE users SET emailDigest = ? WHERE id = ?", [enabled ? 1 : 0, userId]);
    return this.getUser(userId);
  }
  async listDigestRecipients(): Promise<User[]> {
    return (await this.all("SELECT * FROM users WHERE emailDigest = 1")).map(rowToUser).filter((u): u is User => !!u);
  }
  async markDigestSent(userId: string, iso: string): Promise<void> {
    await this.run("UPDATE users SET lastDigestAt = ? WHERE id = ?", [iso, userId]);
  }
  // Sealed here rather than at the route — see the note in db.ts.
  async setUserDeepseekKey(userId: string, key: string | null): Promise<void> {
    const trimmed = key && key.trim() ? key.trim() : null;
    await this.run("UPDATE users SET deepseekApiKey = ? WHERE id = ?", [trimmed ? sealSecret(trimmed) : null, userId]);
  }
  async getUserDeepseekKey(userId: string): Promise<string | null> {
    const row = await this.get("SELECT deepseekApiKey FROM users WHERE id = ?", [userId]);
    return openSecret(row?.deepseekApiKey ?? null);
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
    await this.tx((q) => this._addCreditsWithin(q, userId, amount, type, stripeSessionId));
    return (await this.getUser(userId))!;
  }
  // Atomic check-and-debit: SELECT ... FOR UPDATE locks the user row for the
  // duration of the transaction, so a concurrent debit blocks until this one
  // commits and then reads the already-decremented balance — two requests
  // sharing a single credit can't both succeed. (SqliteDb gets the same
  // guarantee for free from its synchronous single-threaded transaction.)
  async deductCredits(userId: string, amount: number): Promise<boolean> {
    return this.tx(async (q) => {
      const user = rowToUser(await this.get("SELECT * FROM users WHERE id = ? FOR UPDATE", [userId], q));
      if (!user || user.credits < amount) return false;
      await this._addCreditsWithin(q, userId, -amount, "scan_debit");
      return true;
    });
  }
  async listTransactions(userId: string): Promise<CreditTransaction[]> {
    return this.all("SELECT * FROM transactions WHERE userId = ? ORDER BY createdAt DESC", [userId]) as Promise<CreditTransaction[]>;
  }
  async hasTransactionForSession(sessionId: string): Promise<boolean> {
    return !!(await this.get("SELECT 1 FROM transactions WHERE stripeSessionId = ? LIMIT 1", [sessionId]));
  }

  // --- Scans ----------------------------------------------------------------
  async listScans(userId: string): Promise<Scan[]> {
    return (await this.all("SELECT * FROM scans WHERE userId = ? ORDER BY createdAt DESC", [userId])).map((r) => rowToScan(r)!).filter(Boolean);
  }
  async getScan(id: string): Promise<Scan | undefined> {
    return rowToScan(await this.get("SELECT * FROM scans WHERE id = ?", [id]));
  }
  async getPreviousCompletedScan(userId: string, url: string, excludeScanId: string): Promise<Scan | undefined> {
    return rowToScan(await this.get("SELECT * FROM scans WHERE userId = ? AND url = ? AND status = 'complete' AND id != ? ORDER BY createdAt DESC LIMIT 1", [userId, url, excludeScanId]));
  }
  async getLatestScanForUrl(userId: string, url: string): Promise<Scan | undefined> {
    return rowToScan(await this.get("SELECT * FROM scans WHERE userId = ? AND url = ? ORDER BY createdAt DESC LIMIT 1", [userId, url]));
  }
  async createShareToken(userId: string, scanId: string): Promise<string | null> {
    const scan = await this.getScan(scanId);
    if (!scan || scan.userId !== userId || scan.status !== "complete") return null;
    if (scan.shareToken) return scan.shareToken;
    const token = "shr_" + crypto.randomBytes(16).toString("hex");
    await this.run("UPDATE scans SET shareToken = ? WHERE id = ? AND userId = ?", [token, scanId, userId]);
    return token;
  }
  async revokeShareToken(userId: string, scanId: string): Promise<boolean> {
    return (await this.run("UPDATE scans SET shareToken = NULL WHERE id = ? AND userId = ? AND shareToken IS NOT NULL", [scanId, userId])) > 0;
  }
  async getScanByShareToken(token: string): Promise<Scan | undefined> {
    if (!token) return undefined;
    return rowToScan(await this.get("SELECT * FROM scans WHERE shareToken = ?", [token]));
  }
  async createScan(userId: string, url: string, authHeader?: string): Promise<Scan> {
    const id = "scan_" + crypto.randomBytes(8).toString("hex");
    const now = new Date().toISOString();
    await this.run("INSERT INTO scans (id, userId, url, authHeader, status, createdAt) VALUES (?, ?, ?, ?, ?, ?)", [id, userId, url, authHeader ?? null, "queued", now]);
    return (await this.getScan(id))!;
  }
  async deleteAllScans(userId: string): Promise<number> {
    return this.tx(async (q) => {
      const n = await this.run("DELETE FROM scans WHERE userId = ?", [userId], q);
      await this.run("UPDATE monitored_targets SET lastScannedAt = NULL WHERE userId = ?", [userId], q);
      return n;
    });
  }
  // See SqliteDb.claimMonitoredTick for why this is not done through nextRun.
  async claimMonitoredTick(targetId: string, staleBeforeIso: string, nowIso: string): Promise<boolean> {
    const r = await this.pool.query(
      'UPDATE monitored_targets SET claimedAt = $1 WHERE id = $2 AND (claimedAt IS NULL OR claimedAt < $3)',
      [nowIso, targetId, staleBeforeIso]);
    return (r.rowCount ?? 0) === 1;
  }

  async releaseMonitoredTick(targetId: string): Promise<void> {
    await this.pool.query('UPDATE monitored_targets SET claimedAt = NULL WHERE id = $1', [targetId]);
  }

  // See SqliteDb.claimDigestSend — one statement so the check and the write
  // cannot be split by another replica ticking at the same moment.
  async claimDigestSend(userId: string, notSinceIso: string, nowIso: string): Promise<boolean> {
    const r = await this.pool.query(
      'UPDATE users SET lastDigestAt = $1 WHERE id = $2 AND (lastDigestAt IS NULL OR lastDigestAt < $3)',
      [nowIso, userId, notSinceIso]);
    return (r.rowCount ?? 0) === 1;
  }

  async claimMonitoredRun(targetId: string, dueBeforeIso: string, nextRunIso: string): Promise<boolean> {
    const r = await this.pool.query(
      'UPDATE monitored_targets SET nextRun = $1 WHERE id = $2 AND nextRun <= $3',
      [nextRunIso, targetId, dueBeforeIso]);
    return (r.rowCount ?? 0) === 1;
  }

  async enqueueScanJob(scanId: string, params: { allowActiveProbes: boolean; allowAggressiveProbes?: boolean }): Promise<void> {
    await this.pool.query('UPDATE scans SET jobParams = $1, heartbeatAt = NULL WHERE id = $2',
      [JSON.stringify(params), scanId]);
  }

  // One statement, so the select and the lease cannot be split by another
  // worker. FOR UPDATE SKIP LOCKED is what makes this scale: concurrent workers
  // step over each other's locked rows and each takes a different scan, instead
  // of serialising on the head of the queue or colliding on the same one.
  async claimNextQueuedScan(): Promise<{ scanId: string; params: { allowActiveProbes: boolean; allowAggressiveProbes?: boolean } } | null> {
    const cutoff = new Date(Date.now() - STALE_LEASE_MS).toISOString();
    const now = new Date().toISOString();
    const r = await this.pool.query(
      `UPDATE scans SET heartbeatAt = $1
         WHERE id = (
           SELECT id FROM scans
             WHERE status = 'queued' AND jobParams IS NOT NULL
               AND (heartbeatAt IS NULL OR heartbeatAt < $2)
             ORDER BY createdAt
             LIMIT 1
             FOR UPDATE SKIP LOCKED
         )
       RETURNING id, jobParams`,
      [now, cutoff]);
    const row = r.rows[0];
    if (!row) return null;
    try {
      return { scanId: String(row.id), params: JSON.parse(String(row.jobparams ?? row.jobParams)) };
    } catch {
      return null;
    }
  }

  async touchScan(scanId: string): Promise<void> {
    await this.pool.query('UPDATE scans SET heartbeatAt = $1 WHERE id = $2', [new Date().toISOString(), scanId]);
  }

  // schema.sql is applied out of band, so a deploy shipping only code would find
  // no heartbeatAt column and every lease refresh would throw.
  async ensureScanLeaseSchema(): Promise<void> {
    await this.pool.query('ALTER TABLE scans ADD COLUMN IF NOT EXISTS heartbeatAt text');
    await this.pool.query('ALTER TABLE scans ADD COLUMN IF NOT EXISTS jobParams text');
    await this.pool.query('ALTER TABLE monitored_targets ADD COLUMN IF NOT EXISTS claimedAt text');
  }

  async recoverStuckScans(): Promise<number> {
    // Only scans NOBODY still owns — see SqliteDb.recoverStuckScans for why.
    // Taking every in-flight scan unconditionally is correct on one instance and
    // destructive on several: any replica booting would fail and refund the
    // scans every OTHER replica was actively running.
    const cutoff = new Date(Date.now() - STALE_LEASE_MS).toISOString();
    const stuck = await this.all(
      "SELECT id, userId FROM scans WHERE status IN ('queued', 'scanning', 'analyzing') AND (heartbeatAt IS NULL OR heartbeatAt < ?)",
      [cutoff]);
    if (stuck.length === 0) return 0;
    const now = new Date().toISOString();
    await this.tx(async (q) => {
      for (const s of stuck) {
        await this.run("UPDATE scans SET status = 'failed', error = ?, completedAt = ? WHERE id = ?",
          ["This scan was interrupted by a server restart and could not be resumed. Your credit has been refunded — please launch a new scan.", now, s.id], q);
        await this._addCreditsWithin(q, s.userId, 1, "purchase");
      }
    });
    return stuck.length;
  }
  async cancelScan(userId: string, scanId: string): Promise<Scan | null> {
    const scan = await this.getScan(scanId);
    if (!scan || scan.userId !== userId) return null;
    if (!["queued", "scanning", "analyzing"].includes(scan.status)) return null;
    const now = new Date().toISOString();
    await this.tx(async (q) => {
      await this.run("UPDATE scans SET status = 'canceled', error = ?, completedAt = ? WHERE id = ?", ["Canceled by user.", now, scanId], q);
      await this._addCreditsWithin(q, userId, 1, "purchase");
    });
    return (await this.getScan(scanId))!;
  }
  async updateScan(id: string, updates: Partial<Scan>): Promise<Scan> {
    const existing = await this.getScan(id);
    if (!existing) throw new Error("Scan not found");
    const m = { ...existing, ...updates };
    await this.run(
      // AND status != 'canceled': a late worker write must never clobber a
      // user's cancellation (terminal). Mirrors SqliteDb.updateScan.
      "UPDATE scans SET status = ?, score = ?, severity = ?, findings = ?, aiSummary = ?, aiReasoning = ?, narrationLog = ?, executiveBreakdown = ?, evidence = ?, error = ?, completedAt = ? WHERE id = ? AND status != 'canceled'",
      [m.status, m.score ?? null, m.severity ?? null, m.findings ? JSON.stringify(m.findings) : null, m.aiSummary ?? null, m.aiReasoning ?? null,
       m.narrationLog ? JSON.stringify(m.narrationLog) : null, m.executiveBreakdown ? JSON.stringify(m.executiveBreakdown) : null,
       m.evidence ? JSON.stringify(m.evidence) : null, m.error ?? null, m.completedAt ?? null, id]);
    return (await this.getScan(id))!;
  }

  // --- Out-of-band collaborator ---------------------------------------------
  async registerOobToken(token: string, scanId?: string): Promise<void> {
    // Postgres: ON CONFLICT DO NOTHING replaces SQLite's INSERT OR IGNORE.
    await this.run("INSERT INTO oob_tokens (token, scanId, createdAt) VALUES (?, ?, ?) ON CONFLICT (token) DO NOTHING", [token, scanId ?? null, new Date().toISOString()]);
  }
  async recordOobEvent(token: string, ev: { method: string; sourceIp: string; path: string; userAgent?: string }): Promise<boolean> {
    const tok = await this.get("SELECT createdAt FROM oob_tokens WHERE token = ?", [token]);
    if (!tok) return false;
    if (Date.now() - new Date(tok.createdAt).getTime() > 15 * 60 * 1000) return false;
    const id = "oob_" + crypto.randomBytes(8).toString("hex");
    await this.run("INSERT INTO oob_events (id, token, method, sourceIp, path, userAgent, receivedAt) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [id, token, ev.method, ev.sourceIp, ev.path, ev.userAgent ?? null, new Date().toISOString()]);
    const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    await this.run("DELETE FROM oob_events WHERE receivedAt < ?", [cutoff]);
    await this.run("DELETE FROM oob_tokens WHERE createdAt < ?", [cutoff]);
    return true;
  }
  async getOobEvents(token: string): Promise<OobEvent[]> {
    return this.all("SELECT * FROM oob_events WHERE token = ? ORDER BY receivedAt ASC", [token]) as Promise<OobEvent[]>;
  }

  // --- Network Reconnaissance (nmap) ----------------------------------------
  async createNmapScan(userId: string, url: string, deep = false): Promise<NmapScan> {
    const id = "nmap_" + crypto.randomBytes(8).toString("hex");
    const now = new Date().toISOString();
    await this.run("INSERT INTO nmap_scans (id, userId, url, status, deep, createdAt) VALUES (?, ?, ?, ?, ?, ?)", [id, userId, url, "queued", deep ? 1 : 0, now]);
    return (await this.getNmapScan(id))!;
  }
  async getNmapScan(id: string): Promise<NmapScan | undefined> {
    return rowToNmapScan(await this.get("SELECT * FROM nmap_scans WHERE id = ?", [id]));
  }
  async listNmapScans(userId: string): Promise<NmapScan[]> {
    return (await this.all("SELECT * FROM nmap_scans WHERE userId = ? ORDER BY createdAt DESC", [userId])).map((r) => rowToNmapScan(r)!).filter(Boolean);
  }
  async updateNmapScan(id: string, updates: Partial<NmapScan>): Promise<NmapScan> {
    const existing = await this.getNmapScan(id);
    if (!existing) throw new Error("Nmap scan not found");
    const m = { ...existing, ...updates };
    await this.run(
      // See updateScan: never overwrite a cancellation.
      "UPDATE nmap_scans SET status = ?, resolvedIp = ?, nmapVersion = ?, result = ?, rawXml = ?, error = ?, startedAt = ?, completedAt = ? WHERE id = ? AND status != 'canceled'",
      [m.status, m.resolvedIp ?? null, m.nmapVersion ?? null, m.result ? JSON.stringify(m.result) : null, m.rawXml ?? null, m.error ?? null, m.startedAt ?? null, m.completedAt ?? null, id]);
    return (await this.getNmapScan(id))!;
  }
  async cancelNmapScan(userId: string, scanId: string): Promise<NmapScan | null> {
    const scan = await this.getNmapScan(scanId);
    if (!scan || scan.userId !== userId) return null;
    if (!["queued", "scanning"].includes(scan.status)) return null;
    const now = new Date().toISOString();
    await this.tx(async (q) => {
      await this.run("UPDATE nmap_scans SET status = 'canceled', error = ?, completedAt = ? WHERE id = ?", ["Canceled by user.", now, scanId], q);
      await this._addCreditsWithin(q, userId, 1, "purchase");
    });
    return (await this.getNmapScan(scanId))!;
  }
  async recoverStuckNmapScans(): Promise<number> {
    const stuck = await this.all("SELECT id, userId FROM nmap_scans WHERE status IN ('queued', 'scanning')");
    if (stuck.length === 0) return 0;
    const now = new Date().toISOString();
    await this.tx(async (q) => {
      for (const s of stuck) {
        await this.run("UPDATE nmap_scans SET status = 'failed', error = ?, completedAt = ? WHERE id = ?",
          ["This scan was interrupted by a server restart and could not be resumed. Your credit has been refunded — please launch a new scan.", now, s.id], q);
        await this._addCreditsWithin(q, s.userId, 1, "purchase");
      }
    });
    return stuck.length;
  }
  async hasInFlightNmapScan(userId: string): Promise<boolean> {
    return !!(await this.get("SELECT 1 FROM nmap_scans WHERE userId = ? AND status IN ('queued', 'scanning') LIMIT 1", [userId]));
  }

  // --- Autofix sessions -----------------------------------------------------
  async createAutofixSession(userId: string, targetUrl: string, findingTitle: string, findingCategory: string): Promise<AutofixSession> {
    const id = "afx_" + crypto.randomBytes(8).toString("hex");
    const now = new Date().toISOString();
    await this.run("INSERT INTO autofix_sessions (id, userId, targetUrl, findingTitle, findingCategory, status, turns, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)",
      [id, userId, targetUrl, findingTitle, findingCategory, "active", now, now]);
    return (await this.getAutofixSession(id))!;
  }
  async getAutofixSession(id: string): Promise<AutofixSession | undefined> {
    return rowToAutofixSession(await this.get("SELECT * FROM autofix_sessions WHERE id = ?", [id]));
  }
  async incrementAutofixTurn(id: string): Promise<AutofixSession> {
    const existing = await this.getAutofixSession(id);
    if (!existing) throw new Error("Autofix session not found");
    await this.run("UPDATE autofix_sessions SET turns = turns + 1, updatedAt = ? WHERE id = ?", [new Date().toISOString(), id]);
    return (await this.getAutofixSession(id))!;
  }
  async completeAutofixSession(id: string, status: "done" | "expired" = "done"): Promise<AutofixSession> {
    const existing = await this.getAutofixSession(id);
    if (!existing) throw new Error("Autofix session not found");
    await this.run("UPDATE autofix_sessions SET status = ?, updatedAt = ? WHERE id = ?", [status, new Date().toISOString(), id]);
    return (await this.getAutofixSession(id))!;
  }

  // --- API Keys -------------------------------------------------------------
  async listApiKeys(userId: string): Promise<ApiKey[]> {
    return (await this.all("SELECT * FROM api_keys WHERE userId = ?", [userId])).map((r) => rowToApiKey(r));
  }
  async generateApiKey(userId: string): Promise<{ apiKey: ApiKey; rawKey: string }> {
    const user = await this.getUser(userId);
    if (!user) throw new Error("User not found");
    const id = "key_" + crypto.randomBytes(8).toString("hex");
    const rawKey = "sl_live_" + crypto.randomBytes(16).toString("hex");
    await this.run("INSERT INTO api_keys (id, userId, key, keyPreview, credits, active, createdAt) VALUES (?, ?, ?, ?, ?, 1, ?)",
      [id, userId, hashToken(rawKey), maskKey(rawKey), user.credits, new Date().toISOString()]);
    return { apiKey: rowToApiKey(await this.get("SELECT * FROM api_keys WHERE id = ?", [id])), rawKey };
  }
  async revokeApiKey(userId: string, keyId: string): Promise<boolean> {
    return (await this.run("UPDATE api_keys SET active = 0 WHERE id = ? AND userId = ?", [keyId, userId])) > 0;
  }
  async validateApiKeyAndDeduct(apiKeyString: string, quantity = 1): Promise<User | null> {
    const keyRow = await this.get("SELECT * FROM api_keys WHERE key = ?", [hashToken(apiKeyString)]);
    if (!keyRow || !keyRow.active) return null;
    // Lock the user row and check-then-debit atomically (see deductCredits).
    return this.tx(async (q) => {
      const user = rowToUser(await this.get("SELECT * FROM users WHERE id = ? FOR UPDATE", [keyRow.userId], q));
      if (!user || user.credits < quantity) return null;
      await this._addCreditsWithin(q, keyRow.userId, -quantity, "scan_debit");
      return rowToUser(await this.get("SELECT * FROM users WHERE id = ?", [keyRow.userId], q)) ?? null;
    });
  }
  async validateApiKey(apiKeyString: string): Promise<User | null> {
    const keyRow = await this.get("SELECT * FROM api_keys WHERE key = ?", [hashToken(apiKeyString)]);
    if (!keyRow || !keyRow.active) return null;
    return (await this.getUser(keyRow.userId)) ?? null;
  }

  // --- Domain verification --------------------------------------------------
  async listDomainVerifications(userId: string): Promise<DomainVerification[]> {
    return (await this.all("SELECT * FROM domain_verifications WHERE userId = ? ORDER BY createdAt DESC", [userId])).map((r) => rowToDomainVerification(r)!);
  }
  async getDomainVerification(userId: string, domain: string): Promise<DomainVerification | undefined> {
    return rowToDomainVerification(await this.get("SELECT * FROM domain_verifications WHERE userId = ? AND domain = ?", [userId, domain]));
  }
  async startDomainVerification(userId: string, domain: string, token: string): Promise<DomainVerification> {
    const existing = await this.getDomainVerification(userId, domain);
    if (existing) return existing;
    const id = "dv_" + crypto.randomBytes(8).toString("hex");
    await this.run("INSERT INTO domain_verifications (id, userId, domain, token, verified, createdAt) VALUES (?, ?, ?, ?, 0, ?)", [id, userId, domain, token, new Date().toISOString()]);
    return (await this.getDomainVerification(userId, domain))!;
  }
  async markDomainVerified(userId: string, domain: string, method: "dns" | "file" = "dns"): Promise<void> {
    await this.run("UPDATE domain_verifications SET verified = 1, verifiedAt = ?, method = ? WHERE userId = ? AND domain = ?", [new Date().toISOString(), method, userId, domain]);
  }
  async isDomainVerified(userId: string, domain: string): Promise<boolean> {
    return !!(await this.getDomainVerification(userId, domain))?.verified;
  }

  // --- Suppression rules ----------------------------------------------------
  async listSuppressions(userId: string): Promise<SuppressionRule[]> {
    return this.all("SELECT * FROM suppressions WHERE userId = ?", [userId]) as Promise<SuppressionRule[]>;
  }
  async addSuppression(userId: string, targetUrl: string, findingTitle: string, reason: string): Promise<SuppressionRule> {
    const id = "supp_" + crypto.randomBytes(8).toString("hex");
    const rule: SuppressionRule = { id, userId, targetUrl, findingTitle, reason, createdAt: new Date().toISOString() };
    await this.run("INSERT INTO suppressions (id, userId, targetUrl, findingTitle, reason, createdAt) VALUES (?, ?, ?, ?, ?, ?)", [id, userId, targetUrl, findingTitle, reason, rule.createdAt]);
    return rule;
  }
  async removeSuppression(userId: string, ruleId: string): Promise<boolean> {
    return (await this.run("DELETE FROM suppressions WHERE id = ? AND userId = ?", [ruleId, userId])) > 0;
  }

  // --- Monitored targets ----------------------------------------------------
  async listMonitoredTargets(userId: string): Promise<MonitoredTarget[]> {
    return (await this.all("SELECT * FROM monitored_targets WHERE userId = ?", [userId])).map(rowToMonitoredTarget);
  }
  async getMonitoredTarget(userId: string, id: string): Promise<MonitoredTarget | undefined> {
    const row = await this.get("SELECT * FROM monitored_targets WHERE id = ? AND userId = ?", [id, userId]);
    return row ? rowToMonitoredTarget(row) : undefined;
  }
  async addMonitoredTarget(userId: string, url: string, schedule: number | MonitorSchedule): Promise<MonitoredTarget> {
    const s: MonitorSchedule = typeof schedule === "number" ? { frequencyDays: schedule } : schedule;
    const id = "mon_" + crypto.randomBytes(8).toString("hex");
    const now = new Date().toISOString();
    const nextScanAt = computeNextRun(new Date(), s).toISOString();
    await this.run("INSERT INTO monitored_targets (id, userId, url, frequencyDays, scheduleString, scanHour, scanMinute, scanWeekday, nextScanAt, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      [id, userId, url, s.frequencyDays, describeSchedule(s), s.hour ?? null, s.minute ?? null, s.weekday ?? null, nextScanAt, now]);
    return rowToMonitoredTarget(await this.get("SELECT * FROM monitored_targets WHERE id = ?", [id]));
  }
  async removeMonitoredTarget(userId: string, id: string): Promise<boolean> {
    return (await this.run("DELETE FROM monitored_targets WHERE id = ? AND userId = ?", [id, userId])) > 0;
  }
  async setMonitoredPaused(userId: string, id: string, paused: boolean): Promise<boolean> {
    return (await this.run("UPDATE monitored_targets SET paused = ? WHERE id = ? AND userId = ?", [paused ? 1 : 0, id, userId])) > 0;
  }
  async updateMonitoredSchedule(userId: string, id: string, schedule: MonitorSchedule): Promise<MonitoredTarget | undefined> {
    const nextScanAt = computeNextRun(new Date(), schedule).toISOString();
    const changed = await this.run("UPDATE monitored_targets SET frequencyDays = ?, scheduleString = ?, scanHour = ?, scanMinute = ?, scanWeekday = ?, nextScanAt = ? WHERE id = ? AND userId = ?",
      [schedule.frequencyDays, describeSchedule(schedule), schedule.hour ?? null, schedule.minute ?? null, schedule.weekday ?? null, nextScanAt, id, userId]);
    return changed > 0 ? this.getMonitoredTarget(userId, id) : undefined;
  }
  async listDueMonitoredTargets(nowIso: string): Promise<MonitoredTarget[]> {
    return (await this.all("SELECT * FROM monitored_targets WHERE nextScanAt IS NOT NULL AND nextScanAt <= ? AND (paused IS NULL OR paused = 0)", [nowIso])).map(rowToMonitoredTarget);
  }
  async markMonitoredScanned(id: string, lastScannedAt: string, nextScanAt: string): Promise<void> {
    await this.run("UPDATE monitored_targets SET lastScannedAt = ?, nextScanAt = ?, lastError = NULL WHERE id = ?", [lastScannedAt, nextScanAt, id]);
  }
  async markMonitoredSkipped(id: string, nextScanAt: string, error: string): Promise<void> {
    await this.run("UPDATE monitored_targets SET nextScanAt = ?, lastError = ? WHERE id = ?", [nextScanAt, error, id]);
  }
  async markMonitoredError(id: string, error: string): Promise<void> {
    await this.run("UPDATE monitored_targets SET lastError = ? WHERE id = ?", [error, id]);
  }

  // --- Read-model + health/lifecycle ----------------------------------------
  async getScanWithSuppressedFindings(scan: Scan): Promise<Scan> {
    if (!scan || !scan.findings) return scan;
    const rules = await this.listSuppressions(scan.userId);
    const scanUrlClean = cleanUrl(scan.url);
    const findings = scan.findings.map((finding) => {
      const rule = rules.find((r) => cleanUrl(r.targetUrl) === scanUrlClean && r.findingTitle === finding.title);
      if (rule) return { ...finding, isFalsePositive: true, suppressionReason: rule.reason, suppressedAt: rule.createdAt };
      const { isFalsePositive, suppressionReason, suppressedAt, ...rest } = finding;
      return rest as Finding;
    });
    const { score, severity } = scoreFindings(findings);
    return { ...scan, findings, score, severity };
  }
  async healthy(): Promise<boolean> {
    try { await this.pool.query("SELECT 1"); return true; } catch { return false; }
  }
  // Postgres backups are managed (Supabase snapshots / pg_dump), not a per-file
  // VACUUM INTO like SQLite — so this is a no-op. The backup worker is a no-op on
  // Postgres too (see server.ts wiring).
  async appendScanEvents(scanId: string, events: { seq: number; ts: number; channel: string; text: string }[]): Promise<void> {
    if (!events.length) return;
    // One statement: a scan emits events in bursts, and a round-trip per event
    // would put the database in the middle of the scanner's hot loop.
    const values: unknown[] = [];
    const tuples = events.map((e, i) => {
      values.push(scanId, e.seq, e.ts, e.channel, e.text);
      const b = i * 5;
      return `($${b + 1}, $${b + 2}, $${b + 3}, $${b + 4}, $${b + 5})`;
    });
    // ON CONFLICT DO NOTHING: a retried flush must not fail the scan, and (scanId,
    // seq) is stable, so re-writing the same event is a no-op rather than a dup.
    await this.pool.query(
      `INSERT INTO scan_events (scanId, seq, ts, channel, text) VALUES ${tuples.join(', ')} ON CONFLICT DO NOTHING`,
      values);
  }

  async getScanEventsSince(scanId: string, cursor: number):
      Promise<{ events: { seq: number; ts: number; channel: string; text: string }[]; found: boolean }> {
    const any = await this.pool.query('SELECT 1 FROM scan_events WHERE scanId = $1 LIMIT 1', [scanId]);
    if (!any.rows.length) return { events: [], found: false };
    const r = await this.pool.query(
      'SELECT seq, ts, channel, text FROM scan_events WHERE scanId = $1 AND seq > $2 ORDER BY seq', [scanId, cursor]);
    return {
      events: r.rows.map((row: any) => ({
        seq: Number(row.seq), ts: Number(row.ts), channel: String(row.channel), text: String(row.text),
      })),
      found: true,
    };
  }

  async deleteScanEvents(scanId: string): Promise<void> {
    await this.pool.query('DELETE FROM scan_events WHERE scanId = $1', [scanId]);
  }

  // Creates rate_limit_hits if it is missing. Needed because NOTHING applies
  // server/pg/schema.sql at runtime — it is applied out of band by
  // scripts/migrate-sqlite-to-pg.ts — so a deploy that merely ships this code
  // would find no table, throw on every rate-limited request, fail open (see
  // rateLimit()) and silently disable rate limiting while filling the log.
  // Idempotent, and scoped to this one transient table; the domain schema
  // stays owned by schema.sql.
  async ensureRateLimitSchema(): Promise<void> {
    await this.pool.query(
      'CREATE TABLE IF NOT EXISTS rate_limit_hits (bucketKey text NOT NULL, hitAt bigint NOT NULL)');
    await this.pool.query(
      'CREATE INDEX IF NOT EXISTS idx_rate_limit_hits_key ON rate_limit_hits(bucketKey, hitAt)');
  }

  // Same reason as ensureRateLimitSchema: server/pg/schema.sql is applied out
  // of band, so a deploy that only ships code would find no table and every
  // event flush would fail.
  async ensureScanEventSchema(): Promise<void> {
    await this.pool.query(
      'CREATE TABLE IF NOT EXISTS scan_events (scanId text NOT NULL, seq integer NOT NULL, ts bigint NOT NULL, channel text NOT NULL, text text NOT NULL, PRIMARY KEY (scanId, seq))');
    await this.pool.query(
      'CREATE INDEX IF NOT EXISTS idx_scan_events_scan ON scan_events(scanId, seq)');
  }

  // Shared sliding-window rate limit (see SqliteDb.rateLimitHit). One statement
  // so the prune, the count and the insert all run against the same snapshot
  // and a replica cannot be preempted between them.
  //
  // The insert is conditional on the count, so a request that is already over
  // the limit does not add another row and push its own retry time further out.
  async rateLimitHit(bucketKey: string, windowMs: number, max: number, now = Date.now()):
      Promise<{ limited: boolean; retryAfterSec: number }> {
    const windowStart = now - windowMs;
    const sql = `
      WITH pruned AS (
        DELETE FROM rate_limit_hits WHERE bucketKey = $1 AND hitAt < $2
      ), cur AS (
        SELECT count(*)::int AS n, min(hitAt) AS oldest
        FROM rate_limit_hits WHERE bucketKey = $1 AND hitAt >= $2
      ), ins AS (
        INSERT INTO rate_limit_hits (bucketKey, hitAt)
        SELECT $1, $3 FROM cur WHERE cur.n < $4
        RETURNING 1
      )
      SELECT cur.n, cur.oldest, (SELECT count(*) FROM ins)::int AS inserted FROM cur`;
    const r = await this.pool.query(sql, [bucketKey, windowStart, now, max]);
    const row = (r.rows[0] ?? { n: 0, oldest: null, inserted: 1 }) as
      { n: number; oldest: string | number | null; inserted: number };
    if (row.inserted > 0) return { limited: false, retryAfterSec: 0 };
    const oldest = row.oldest === null ? now : Number(row.oldest);
    return { limited: true, retryAfterSec: Math.max(1, Math.ceil((windowMs - (now - oldest)) / 1000)) };
  }

  // Postgres snapshots are the platform's job (Railway PITR / scheduled
  // backups), not this process's. Returning false — rather than silently
  // resolving — is what stops the backup worker reporting a snapshot it
  // never took: it used to log "Wrote snapshot <name>" every 24h against a
  // file that did not exist, so the logs read healthy while nothing was
  // being backed up at all.
  async backupTo(_destPath: string): Promise<boolean> { return false; }
  async close(): Promise<void> {
    try { await this.pool.end(); } catch (err: any) { console.warn("[pgDb] Error while closing pool:", err?.message || err); }
  }
}
