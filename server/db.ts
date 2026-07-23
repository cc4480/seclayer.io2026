import path from 'path';
import crypto from 'crypto';
import Database from 'better-sqlite3';
import { User, Scan, CreditTransaction, ApiKey, Finding, SuppressionRule, MonitoredTarget, DomainVerification, OobEvent } from '../src/types.js';
import { scoreFindings } from './scoring.js';
import { MonitorSchedule, computeNextRun, describeSchedule } from './schedule.js';
import { runMigrations } from './dbSchema.js';
import { rowToUser, rowToScan, rowToApiKey, rowToDomainVerification } from './dbMappers.js';
import { hashToken, maskKey } from './dbCrypto.js';

const DB_FILE = process.env.DB_PATH || path.join(process.cwd(), 'data.sqlite');

// --- URL + scoring helpers ---------------------------------------------------
export function cleanUrl(urlStr: string): string {
  try {
    return urlStr.replace(/https?:\/\//i, '').replace(/\/+$/, '').trim().toLowerCase();
  } catch {
    return String(urlStr || '').trim().toLowerCase();
  }
}

// Re-exported for callers/tests that recompute a score from a finding set.
export const recalculateScore = scoreFindings;

class SqliteDb {
  private db: Database.Database;

  constructor() {
    this.db = new Database(DB_FILE);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    runMigrations(this.db);
  }

  // --- Magic-link auth + sessions ---
  // Tokens are random secrets; only their SHA-256 hash is persisted (see
  // dbCrypto.hashToken) so a DB read cannot reveal a usable login/session token.

  // Issues a single-use magic-link token (default 15 min TTL). Returns the raw
  // token to embed in the emailed link; only its hash is stored.
  createLoginToken(email: string, ttlMs = 15 * 60 * 1000): string {
    const raw = crypto.randomBytes(32).toString('hex');
    const now = Date.now();
    this.db.prepare('INSERT INTO login_tokens (tokenHash, email, expiresAt, createdAt) VALUES (?, ?, ?, ?)')
      .run(hashToken(raw), email.toLowerCase().trim(), new Date(now + ttlMs).toISOString(), new Date(now).toISOString());
    return raw;
  }

  // Validates and burns a magic-link token, returning the associated email.
  consumeLoginToken(raw: string): string | null {
    const hash = hashToken(raw);
    const row: any = this.db.prepare('SELECT * FROM login_tokens WHERE tokenHash = ?').get(hash);
    if (!row || row.consumedAt) return null;
    if (new Date(row.expiresAt).getTime() < Date.now()) return null;
    this.db.prepare('UPDATE login_tokens SET consumedAt = ? WHERE tokenHash = ?').run(new Date().toISOString(), hash);
    return row.email;
  }

  // Creates a server-side session (default 30 day TTL). Returns the raw token
  // to set as an httpOnly cookie; only its hash is stored.
  createSession(userId: string, ttlMs = 30 * 24 * 60 * 60 * 1000): string {
    const raw = crypto.randomBytes(32).toString('hex');
    const now = Date.now();
    this.db.prepare('INSERT INTO sessions (tokenHash, userId, expiresAt, createdAt) VALUES (?, ?, ?, ?)')
      .run(hashToken(raw), userId, new Date(now + ttlMs).toISOString(), new Date(now).toISOString());
    return raw;
  }

  // Resolves a session cookie to a userId, or null if missing/expired.
  getSessionUserId(raw: string): string | null {
    const row: any = this.db.prepare('SELECT * FROM sessions WHERE tokenHash = ?').get(hashToken(raw));
    if (!row) return null;
    if (new Date(row.expiresAt).getTime() < Date.now()) {
      this.db.prepare('DELETE FROM sessions WHERE tokenHash = ?').run(row.tokenHash);
      return null;
    }
    return row.userId;
  }

  deleteSession(raw: string): void {
    this.db.prepare('DELETE FROM sessions WHERE tokenHash = ?').run(hashToken(raw));
  }

  setUserWebhook(userId: string, url: string | null): User | undefined {
    this.db.prepare("UPDATE users SET notifyWebhook = ? WHERE id = ?").run(url, userId);
    return this.getUser(userId);
  }

  // --- Users ---
  getUser(id: string): User | undefined {
    return rowToUser(this.db.prepare('SELECT * FROM users WHERE id = ?').get(id));
  }

  getUserByEmail(email: string): User | undefined {
    return rowToUser(
      this.db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim())
    );
  }

  getOrCreateUser(email: string): User {
    const normEmail = email.toLowerCase().trim();
    const existing = this.getUserByEmail(normEmail);
    if (existing) return existing;

    const id = 'user_' + crypto.randomBytes(6).toString('hex');
    const now = new Date().toISOString();

    // No API key is provisioned here: a key's raw value is only ever shown
    // once, at the moment generateApiKey() creates it (see below), so a key
    // created out-of-band at signup could never be displayed to its owner.
    // The user generates their first key from the dashboard instead.
    const tx = this.db.transaction(() => {
      this.db.prepare('INSERT INTO users (id, email, credits, createdAt) VALUES (?, ?, ?, ?)')
        .run(id, normEmail, 5, now); // 5 signup credits
      this.db.prepare('INSERT INTO transactions (id, userId, amount, type, createdAt) VALUES (?, ?, ?, ?, ?)')
        .run('tx-signup-' + id, id, 5, 'purchase', now);
    });
    tx();
    return this.getUser(id)!;
  }

  addCredits(userId: string, amount: number, type: 'purchase' | 'scan_debit', stripeSessionId?: string): User {
    const user = this.getUser(userId);
    if (!user) throw new Error('User not found');
    const newCredits = Math.max(0, user.credits + amount);

    const tx = this.db.transaction(() => {
      this.db.prepare('UPDATE users SET credits = ? WHERE id = ?').run(newCredits, userId);
      this.db.prepare('UPDATE api_keys SET credits = ? WHERE userId = ? AND active = 1').run(newCredits, userId);
      this.db.prepare('INSERT INTO transactions (id, userId, amount, type, stripeSessionId, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
        .run('tx_' + crypto.randomBytes(8).toString('hex'), userId, amount, type, stripeSessionId ?? null, new Date().toISOString());
    });
    tx();
    return this.getUser(userId)!;
  }

  deductCredits(userId: string, amount: number): boolean {
    const user = this.getUser(userId);
    if (!user || user.credits < amount) return false;
    this.addCredits(userId, -amount, 'scan_debit');
    return true;
  }

  listTransactions(userId: string): CreditTransaction[] {
    return this.db.prepare('SELECT * FROM transactions WHERE userId = ? ORDER BY createdAt DESC').all(userId) as CreditTransaction[];
  }

  // Idempotency guard for Stripe webhooks: true if a purchase for this Checkout
  // session was already recorded, so retries never grant duplicate credits.
  hasTransactionForSession(sessionId: string): boolean {
    return !!this.db.prepare('SELECT 1 FROM transactions WHERE stripeSessionId = ? LIMIT 1').get(sessionId);
  }

  // --- Scans ---
  listScans(userId: string): Scan[] {
    const rows = this.db.prepare('SELECT * FROM scans WHERE userId = ? ORDER BY createdAt DESC').all(userId);
    return rows.map(r => rowToScan(r)!).filter(Boolean);
  }

  getScan(id: string): Scan | undefined {
    return rowToScan(this.db.prepare('SELECT * FROM scans WHERE id = ?').get(id));
  }

  // The most recent *completed* scan of the same target for this user, other
  // than `excludeScanId` — the baseline a fresh scan is compared against for
  // monitoring regression detection.
  getPreviousCompletedScan(userId: string, url: string, excludeScanId: string): Scan | undefined {
    return rowToScan(this.db.prepare(
      "SELECT * FROM scans WHERE userId = ? AND url = ? AND status = 'complete' AND id != ? ORDER BY createdAt DESC LIMIT 1"
    ).get(userId, url, excludeScanId));
  }

  // --- Out-of-band collaborator (blind SSRF/RCE proof) ---
  //
  // A token is registered when the scanner mints a callback URL, so the public
  // /api/oob/:token endpoint only records hits for tokens WE issued (and only
  // recent ones) — the endpoint can't be used as an open write-anything store.
  registerOobToken(token: string, scanId?: string): void {
    this.db.prepare('INSERT OR IGNORE INTO oob_tokens (token, scanId, createdAt) VALUES (?, ?, ?)')
      .run(token, scanId ?? null, new Date().toISOString());
  }

  // Records a callback IFF the token was issued by us within the last 15 minutes.
  // Returns true when stored. Opportunistically prunes tokens/events older than a
  // day so the tables can't grow without bound. Unknown/expired tokens are a
  // no-op (the route still returns 200 so it leaks nothing about validity).
  recordOobEvent(
    token: string,
    ev: { method: string; sourceIp: string; path: string; userAgent?: string },
  ): boolean {
    const tok = this.db.prepare('SELECT createdAt FROM oob_tokens WHERE token = ?').get(token) as
      | { createdAt: string }
      | undefined;
    if (!tok) return false;
    if (Date.now() - new Date(tok.createdAt).getTime() > 15 * 60 * 1000) return false;
    const id = 'oob_' + crypto.randomBytes(8).toString('hex');
    this.db.prepare(
      'INSERT INTO oob_events (id, token, method, sourceIp, path, userAgent, receivedAt) VALUES (?, ?, ?, ?, ?, ?, ?)',
    ).run(id, token, ev.method, ev.sourceIp, ev.path, ev.userAgent ?? null, new Date().toISOString());
    const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    this.db.prepare('DELETE FROM oob_events WHERE receivedAt < ?').run(cutoff);
    this.db.prepare('DELETE FROM oob_tokens WHERE createdAt < ?').run(cutoff);
    return true;
  }

  getOobEvents(token: string): OobEvent[] {
    return this.db.prepare('SELECT * FROM oob_events WHERE token = ? ORDER BY receivedAt ASC')
      .all(token) as OobEvent[];
  }

  createScan(userId: string, url: string, authHeader?: string): Scan {
    const id = 'scan_' + crypto.randomBytes(8).toString('hex');
    const now = new Date().toISOString();
    this.db.prepare('INSERT INTO scans (id, userId, url, authHeader, status, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
      .run(id, userId, url, authHeader ?? null, 'queued', now);
    return this.getScan(id)!;
  }

  // Resilience: the job model is in-process and fire-and-forget (see
  // scanWorker.ts), not backed by a persisted queue, so a scan left in
  // queued/scanning/analyzing when the process dies (crash, redeploy, OOM
  // kill) is orphaned — no worker will ever resume it, and it would otherwise
  // stay stuck in that status forever with no terminal state. Called once at
  // boot to fail every such scan cleanly and refund the credit it spent,
  // since the interruption was a platform fault, not the user's.
  recoverStuckScans(): number {
    const stuck = this.db.prepare(
      "SELECT id, userId FROM scans WHERE status IN ('queued', 'scanning', 'analyzing')"
    ).all() as Array<{ id: string; userId: string }>;
    if (stuck.length === 0) return 0;
    const now = new Date().toISOString();
    const tx = this.db.transaction(() => {
      for (const s of stuck) {
        this.db.prepare("UPDATE scans SET status = 'failed', error = ?, completedAt = ? WHERE id = ?").run(
          'This scan was interrupted by a server restart and could not be resumed. Your credit has been refunded — please launch a new scan.',
          now,
          s.id
        );
        this.addCredits(s.userId, 1, 'purchase');
      }
    });
    tx();
    return stuck.length;
  }

  // User-initiated cancellation. Only valid while the scan is still in flight
  // (queued/scanning/analyzing) — a scan that already reached a terminal
  // status can't be canceled after the fact. The credit is refunded since the
  // user never got a report. Note this stops the scan from ever overwriting
  // "canceled" with a late result (see scanWorker.ts's status guard before
  // each write) but does not abort in-flight network probes — the pipeline
  // has no cancellation token threaded through it, so any request already in
  // flight still runs to completion; its result is simply never persisted.
  cancelScan(userId: string, scanId: string): Scan | null {
    const scan = this.getScan(scanId);
    if (!scan || scan.userId !== userId) return null;
    if (!['queued', 'scanning', 'analyzing'].includes(scan.status)) return null;
    const now = new Date().toISOString();
    const tx = this.db.transaction(() => {
      this.db.prepare("UPDATE scans SET status = 'canceled', error = ?, completedAt = ? WHERE id = ?")
        .run('Canceled by user.', now, scanId);
      this.addCredits(userId, 1, 'purchase');
    });
    tx();
    return this.getScan(scanId)!;
  }

  updateScan(id: string, updates: Partial<Scan>): Scan {
    const existing = this.getScan(id);
    if (!existing) throw new Error('Scan not found');
    const merged = { ...existing, ...updates };
    this.db.prepare(`
      UPDATE scans SET status = ?, score = ?, severity = ?, findings = ?, aiSummary = ?, aiReasoning = ?, narrationLog = ?, executiveBreakdown = ?, evidence = ?, error = ?, completedAt = ?
      WHERE id = ?
    `).run(
      merged.status,
      merged.score ?? null,
      merged.severity ?? null,
      merged.findings ? JSON.stringify(merged.findings) : null,
      merged.aiSummary ?? null,
      merged.aiReasoning ?? null,
      merged.narrationLog ? JSON.stringify(merged.narrationLog) : null,
      merged.executiveBreakdown ? JSON.stringify(merged.executiveBreakdown) : null,
      merged.evidence ? JSON.stringify(merged.evidence) : null,
      merged.error ?? null,
      merged.completedAt ?? null,
      id
    );
    return this.getScan(id)!;
  }

  // --- API Keys ---
  listApiKeys(userId: string): ApiKey[] {
    return (this.db.prepare('SELECT * FROM api_keys WHERE userId = ?').all(userId) as any[]).map(r => rowToApiKey(r));
  }

  // Returns the new key row (safe to persist/display forever) alongside the
  // raw secret (safe to show exactly once, in the HTTP response to this call).
  // Only the SHA-256 hash and a masked preview are ever written to disk.
  generateApiKey(userId: string): { apiKey: ApiKey; rawKey: string } {
    const user = this.getUser(userId);
    if (!user) throw new Error('User not found');
    const id = 'key_' + crypto.randomBytes(8).toString('hex');
    const rawKey = 'sl_live_' + crypto.randomBytes(16).toString('hex');
    this.db.prepare('INSERT INTO api_keys (id, userId, key, keyPreview, credits, active, createdAt) VALUES (?, ?, ?, ?, ?, 1, ?)')
      .run(id, userId, hashToken(rawKey), maskKey(rawKey), user.credits, new Date().toISOString());
    const apiKey = rowToApiKey(this.db.prepare('SELECT * FROM api_keys WHERE id = ?').get(id));
    return { apiKey, rawKey };
  }

  revokeApiKey(userId: string, keyId: string): boolean {
    const res = this.db.prepare('UPDATE api_keys SET active = 0 WHERE id = ? AND userId = ?').run(keyId, userId);
    return res.changes > 0;
  }

  validateApiKeyAndDeduct(apiKeyString: string, quantity: number = 1): User | null {
    const keyRow: any = this.db.prepare('SELECT * FROM api_keys WHERE key = ?').get(hashToken(apiKeyString));
    if (!keyRow || !keyRow.active) return null;
    const user = this.getUser(keyRow.userId);
    if (!user || user.credits < quantity) return null;
    return this.addCredits(user.id, -quantity, 'scan_debit');
  }

  // --- Domain Ownership Verification ---
  // Gates the scanner's active exploit probes: only a verified domain unlocks
  // them (see server/domainVerify.ts + scanner.ts's allowActiveProbes option).
  listDomainVerifications(userId: string): DomainVerification[] {
    return (this.db.prepare('SELECT * FROM domain_verifications WHERE userId = ? ORDER BY createdAt DESC').all(userId) as any[])
      .map((r) => rowToDomainVerification(r)!);
  }

  getDomainVerification(userId: string, domain: string): DomainVerification | undefined {
    return rowToDomainVerification(
      this.db.prepare('SELECT * FROM domain_verifications WHERE userId = ? AND domain = ?').get(userId, domain)
    );
  }

  // Creates a pending verification (or returns the existing pending/verified
  // one) so repeated "start" calls hand back the same token/instructions.
  startDomainVerification(userId: string, domain: string, token: string): DomainVerification {
    const existing = this.getDomainVerification(userId, domain);
    if (existing) return existing;
    const id = 'dv_' + crypto.randomBytes(8).toString('hex');
    this.db.prepare('INSERT INTO domain_verifications (id, userId, domain, token, verified, createdAt) VALUES (?, ?, ?, ?, 0, ?)')
      .run(id, userId, domain, token, new Date().toISOString());
    return this.getDomainVerification(userId, domain)!;
  }

  markDomainVerified(userId: string, domain: string, method: 'dns' | 'file' = 'dns'): void {
    this.db.prepare('UPDATE domain_verifications SET verified = 1, verifiedAt = ?, method = ? WHERE userId = ? AND domain = ?')
      .run(new Date().toISOString(), method, userId, domain);
  }

  isDomainVerified(userId: string, domain: string): boolean {
    return !!this.getDomainVerification(userId, domain)?.verified;
  }

  // --- Suppression Rules (False Positive Management) ---
  // Suppression is applied as a read-model (see getScanWithSuppressedFindings),
  // so adding/removing a rule is a simple row mutation with no scan rewrites.
  listSuppressions(userId: string): SuppressionRule[] {
    return this.db.prepare('SELECT * FROM suppressions WHERE userId = ?').all(userId) as SuppressionRule[];
  }

  addSuppression(userId: string, targetUrl: string, findingTitle: string, reason: string): SuppressionRule {
    const id = 'supp_' + crypto.randomBytes(8).toString('hex');
    const rule: SuppressionRule = { id, userId, targetUrl, findingTitle, reason, createdAt: new Date().toISOString() };
    this.db.prepare('INSERT INTO suppressions (id, userId, targetUrl, findingTitle, reason, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
      .run(id, userId, targetUrl, findingTitle, reason, rule.createdAt);
    return rule;
  }

  removeSuppression(userId: string, ruleId: string): boolean {
    const res = this.db.prepare('DELETE FROM suppressions WHERE id = ? AND userId = ?').run(ruleId, userId);
    return res.changes > 0;
  }

  // --- Monitored Targets ---
  listMonitoredTargets(userId: string): MonitoredTarget[] {
    return this.db.prepare('SELECT * FROM monitored_targets WHERE userId = ?').all(userId) as MonitoredTarget[];
  }

  // Accepts either a full schedule (daily/weekly/monthly + time-of-day) or a
  // bare frequency in days (legacy callers). The next run instant and the human
  // scheduleString are both derived from that one schedule so they can't drift.
  addMonitoredTarget(userId: string, url: string, schedule: number | MonitorSchedule): MonitoredTarget {
    const s: MonitorSchedule = typeof schedule === 'number' ? { frequencyDays: schedule } : schedule;
    const id = 'mon_' + crypto.randomBytes(8).toString('hex');
    const now = new Date().toISOString();
    const nextScanAt = computeNextRun(new Date(), s).toISOString();
    this.db.prepare('INSERT INTO monitored_targets (id, userId, url, frequencyDays, scheduleString, scanHour, scanMinute, scanWeekday, nextScanAt, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(id, userId, url, s.frequencyDays, describeSchedule(s), s.hour ?? null, s.minute ?? null, s.weekday ?? null, nextScanAt, now);
    return this.db.prepare('SELECT * FROM monitored_targets WHERE id = ?').get(id) as MonitoredTarget;
  }

  removeMonitoredTarget(userId: string, id: string): boolean {
    const res = this.db.prepare('DELETE FROM monitored_targets WHERE id = ? AND userId = ?').run(id, userId);
    return res.changes > 0;
  }

  // Targets whose next scheduled scan is due (used by the monitoring worker).
  listDueMonitoredTargets(nowIso: string): MonitoredTarget[] {
    return this.db.prepare(
      'SELECT * FROM monitored_targets WHERE nextScanAt IS NOT NULL AND nextScanAt <= ?'
    ).all(nowIso) as MonitoredTarget[];
  }

  // A scan attempt was successfully launched for this tick — clears any
  // lingering error from a previous tick so the UI stops warning about a
  // target that has since recovered.
  markMonitoredScanned(id: string, lastScannedAt: string, nextScanAt: string): void {
    this.db.prepare('UPDATE monitored_targets SET lastScannedAt = ?, nextScanAt = ?, lastError = NULL WHERE id = ?')
      .run(lastScannedAt, nextScanAt, id);
  }

  // The target itself is invalid/unsafe (fails the SSRF guard) — deferred to
  // its next real cadence rather than retried every tick, with the reason
  // recorded so the dashboard can show why this monitor keeps producing no
  // scans instead of silently doing nothing forever.
  markMonitoredSkipped(id: string, nextScanAt: string, error: string): void {
    this.db.prepare('UPDATE monitored_targets SET nextScanAt = ?, lastError = ? WHERE id = ?')
      .run(nextScanAt, error, id);
  }

  // The target itself is fine but this tick couldn't spend a credit (none
  // available) — scheduling is untouched so it's retried next tick, but the
  // reason is still recorded for visibility.
  markMonitoredError(id: string, error: string): void {
    this.db.prepare('UPDATE monitored_targets SET lastError = ? WHERE id = ?').run(error, id);
  }

  // Read-model: returns a scan with suppression rules applied and the score
  // recalculated. This is a PURE transform — it never writes to the database,
  // so reads have no side effects.
  getScanWithSuppressedFindings(scan: Scan): Scan {
    if (!scan || !scan.findings) return scan;
    const rules = this.listSuppressions(scan.userId);
    const scanUrlClean = cleanUrl(scan.url);

    const findings = scan.findings.map((finding) => {
      const rule = rules.find(r => cleanUrl(r.targetUrl) === scanUrlClean && r.findingTitle === finding.title);
      if (rule) {
        return { ...finding, isFalsePositive: true, suppressionReason: rule.reason, suppressedAt: rule.createdAt };
      }
      // Strip any stale suppression metadata if no rule currently matches.
      const { isFalsePositive, suppressionReason, suppressedAt, ...rest } = finding;
      return rest as Finding;
    });

    const { score, severity } = scoreFindings(findings);
    return { ...scan, findings, score, severity };
  }

}

export const db = new SqliteDb();
