import path from 'path';
import crypto from 'crypto';
import Database from 'better-sqlite3';
import { User, Scan, CreditTransaction, ApiKey, Finding, SuppressionRule, MonitoredTarget, DomainVerification, ExecutiveBreakdown } from '../src/types.js';
import { scoreFindings } from './scoring.js';
import { MonitorSchedule, computeNextRun, describeSchedule } from './schedule.js';

const DB_FILE = process.env.DB_PATH || path.join(process.cwd(), 'data.sqlite');

// --- URL + scoring helpers ---------------------------------------------------
export function cleanUrl(urlStr: string): string {
  try {
    return urlStr.replace(/https?:\/\//i, '').replace(/\/+$/, '').trim().toLowerCase();
  } catch {
    return String(urlStr || '').trim().toLowerCase();
  }
}

// A safe-to-display fragment of a secret (prefix + last 4 chars). Never
// reversible back to the real value; used only for listing existing keys.
function maskKey(raw: string): string {
  return raw.length <= 16 ? raw : `${raw.slice(0, 12)}…${raw.slice(-4)}`;
}

const LEGACY_RAW_KEY_PATTERN = /^sl_live_[0-9a-f]{32}$/;

// Re-exported for callers/tests that recompute a score from a finding set.
export const recalculateScore = scoreFindings;

class SqliteDb {
  private db: Database.Database;

  constructor() {
    this.db = new Database(DB_FILE);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.migrate();
  }

  private migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        credits INTEGER NOT NULL DEFAULT 0,
        createdAt TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        url TEXT NOT NULL,
        authHeader TEXT,
        status TEXT NOT NULL,
        score INTEGER,
        severity TEXT,
        findings TEXT,
        aiSummary TEXT,
        error TEXT,
        createdAt TEXT NOT NULL,
        completedAt TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(userId);
      CREATE TABLE IF NOT EXISTS transactions (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        amount INTEGER NOT NULL,
        type TEXT NOT NULL,
        stripeSessionId TEXT,
        createdAt TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_tx_user ON transactions(userId);
      CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        key TEXT UNIQUE NOT NULL,
        credits INTEGER NOT NULL DEFAULT 0,
        active INTEGER NOT NULL DEFAULT 1,
        createdAt TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS domain_verifications (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        domain TEXT NOT NULL,
        token TEXT NOT NULL,
        verified INTEGER NOT NULL DEFAULT 0,
        createdAt TEXT NOT NULL,
        verifiedAt TEXT
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_domain_verif_user_domain ON domain_verifications(userId, domain);
      CREATE INDEX IF NOT EXISTS idx_keys_user ON api_keys(userId);
      CREATE TABLE IF NOT EXISTS suppressions (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        targetUrl TEXT NOT NULL,
        findingTitle TEXT NOT NULL,
        reason TEXT,
        createdAt TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_supp_user ON suppressions(userId);
      CREATE TABLE IF NOT EXISTS monitored_targets (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        url TEXT NOT NULL,
        frequencyDays INTEGER NOT NULL,
        scheduleString TEXT,
        lastScannedAt TEXT,
        nextScanAt TEXT,
        createdAt TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_mon_user ON monitored_targets(userId);
      CREATE TABLE IF NOT EXISTS login_tokens (
        tokenHash TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        expiresAt TEXT NOT NULL,
        consumedAt TEXT,
        createdAt TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS sessions (
        tokenHash TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        expiresAt TEXT NOT NULL,
        createdAt TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(userId);
    `);
    // Additive column migrations (safe across existing databases).
    this.addColumnIfMissing("users", "notifyWebhook", "TEXT");
    this.addColumnIfMissing("api_keys", "keyPreview", "TEXT");
    this.addColumnIfMissing("scans", "aiReasoning", "TEXT");
    this.addColumnIfMissing("scans", "narrationLog", "TEXT");
    this.addColumnIfMissing("scans", "executiveBreakdown", "TEXT");
    this.addColumnIfMissing("scans", "evidence", "TEXT");
    this.addColumnIfMissing("domain_verifications", "method", "TEXT");
    this.addColumnIfMissing("domain_verifications", "attestation", "TEXT");
    this.addColumnIfMissing("monitored_targets", "scanHour", "INTEGER");
    this.addColumnIfMissing("monitored_targets", "scanMinute", "INTEGER");
    this.addColumnIfMissing("monitored_targets", "scanWeekday", "INTEGER");
    this.migrateLegacyPlaintextApiKeys();
  }

  // One-time (idempotent, safe to re-run every boot) upgrade: earlier versions
  // stored API keys in plaintext in api_keys.key. Rewrite any row still in the
  // raw "sl_live_<32 hex>" format to store only its SHA-256 hash, plus a
  // display-safe preview, so a database read alone can never yield a usable key.
  private migrateLegacyPlaintextApiKeys() {
    const rows = this.db.prepare('SELECT id, key FROM api_keys').all() as Array<{ id: string; key: string }>;
    for (const row of rows) {
      if (LEGACY_RAW_KEY_PATTERN.test(row.key)) {
        this.db.prepare('UPDATE api_keys SET key = ?, keyPreview = ? WHERE id = ?')
          .run(this.hashToken(row.key), maskKey(row.key), row.id);
      }
    }
  }

  private addColumnIfMissing(table: string, column: string, decl: string) {
    const cols = this.db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
    if (!cols.some((c) => c.name === column)) {
      this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${decl}`);
    }
  }

  // --- Magic-link auth + sessions ---
  // Tokens are random secrets; only their SHA-256 hash is persisted so a DB
  // read cannot reveal a usable login link or session token.
  private hashToken(raw: string): string {
    return crypto.createHash('sha256').update(raw).digest('hex');
  }

  // Issues a single-use magic-link token (default 15 min TTL). Returns the raw
  // token to embed in the emailed link; only its hash is stored.
  createLoginToken(email: string, ttlMs = 15 * 60 * 1000): string {
    const raw = crypto.randomBytes(32).toString('hex');
    const now = Date.now();
    this.db.prepare('INSERT INTO login_tokens (tokenHash, email, expiresAt, createdAt) VALUES (?, ?, ?, ?)')
      .run(this.hashToken(raw), email.toLowerCase().trim(), new Date(now + ttlMs).toISOString(), new Date(now).toISOString());
    return raw;
  }

  // Validates and burns a magic-link token, returning the associated email.
  consumeLoginToken(raw: string): string | null {
    const hash = this.hashToken(raw);
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
      .run(this.hashToken(raw), userId, new Date(now + ttlMs).toISOString(), new Date(now).toISOString());
    return raw;
  }

  // Resolves a session cookie to a userId, or null if missing/expired.
  getSessionUserId(raw: string): string | null {
    const row: any = this.db.prepare('SELECT * FROM sessions WHERE tokenHash = ?').get(this.hashToken(raw));
    if (!row) return null;
    if (new Date(row.expiresAt).getTime() < Date.now()) {
      this.db.prepare('DELETE FROM sessions WHERE tokenHash = ?').run(row.tokenHash);
      return null;
    }
    return row.userId;
  }

  deleteSession(raw: string): void {
    this.db.prepare('DELETE FROM sessions WHERE tokenHash = ?').run(this.hashToken(raw));
  }

  // --- Row mappers ---
  private rowToUser(row: any): User | undefined {
    if (!row) return undefined;
    return {
      id: row.id, email: row.email, credits: row.credits,
      notifyWebhook: row.notifyWebhook ?? undefined, createdAt: row.createdAt,
    };
  }

  setUserWebhook(userId: string, url: string | null): User | undefined {
    this.db.prepare("UPDATE users SET notifyWebhook = ? WHERE id = ?").run(url, userId);
    return this.getUser(userId);
  }

  private rowToScan(row: any): Scan | undefined {
    if (!row) return undefined;
    return {
      id: row.id,
      userId: row.userId,
      url: row.url,
      authHeader: row.authHeader ?? undefined,
      status: row.status,
      score: row.score ?? undefined,
      severity: row.severity ?? undefined,
      findings: row.findings ? JSON.parse(row.findings) : undefined,
      aiSummary: row.aiSummary ?? undefined,
      aiReasoning: row.aiReasoning ?? undefined,
      narrationLog: row.narrationLog ? JSON.parse(row.narrationLog) : undefined,
      executiveBreakdown: row.executiveBreakdown ? JSON.parse(row.executiveBreakdown) : undefined,
      evidence: row.evidence ? JSON.parse(row.evidence) : undefined,
      error: row.error ?? undefined,
      createdAt: row.createdAt,
      completedAt: row.completedAt ?? undefined,
    };
  }

  private rowToApiKey(row: any): ApiKey {
    return {
      id: row.id, userId: row.userId, keyPreview: row.keyPreview,
      credits: row.credits, active: !!row.active, createdAt: row.createdAt,
    };
  }

  private rowToDomainVerification(row: any): DomainVerification | undefined {
    if (!row) return undefined;
    return {
      id: row.id, userId: row.userId, domain: row.domain, token: row.token,
      verified: !!row.verified, createdAt: row.createdAt, verifiedAt: row.verifiedAt ?? undefined,
      method: row.method ?? undefined, attestation: row.attestation ?? undefined,
    };
  }

  // --- Users ---
  getUser(id: string): User | undefined {
    return this.rowToUser(this.db.prepare('SELECT * FROM users WHERE id = ?').get(id));
  }

  getUserByEmail(email: string): User | undefined {
    return this.rowToUser(
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
    return rows.map(r => this.rowToScan(r)!).filter(Boolean);
  }

  getScan(id: string): Scan | undefined {
    return this.rowToScan(this.db.prepare('SELECT * FROM scans WHERE id = ?').get(id));
  }

  // The most recent *completed* scan of the same target for this user, other
  // than `excludeScanId` — the baseline a fresh scan is compared against for
  // monitoring regression detection.
  getPreviousCompletedScan(userId: string, url: string, excludeScanId: string): Scan | undefined {
    return this.rowToScan(this.db.prepare(
      "SELECT * FROM scans WHERE userId = ? AND url = ? AND status = 'complete' AND id != ? ORDER BY createdAt DESC LIMIT 1"
    ).get(userId, url, excludeScanId));
  }

  createScan(userId: string, url: string, authHeader?: string): Scan {
    const id = 'scan_' + crypto.randomBytes(8).toString('hex');
    const now = new Date().toISOString();
    this.db.prepare('INSERT INTO scans (id, userId, url, authHeader, status, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
      .run(id, userId, url, authHeader ?? null, 'queued', now);
    return this.getScan(id)!;
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
    return (this.db.prepare('SELECT * FROM api_keys WHERE userId = ?').all(userId) as any[]).map(r => this.rowToApiKey(r));
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
      .run(id, userId, this.hashToken(rawKey), maskKey(rawKey), user.credits, new Date().toISOString());
    const apiKey = this.rowToApiKey(this.db.prepare('SELECT * FROM api_keys WHERE id = ?').get(id));
    return { apiKey, rawKey };
  }

  revokeApiKey(userId: string, keyId: string): boolean {
    const res = this.db.prepare('UPDATE api_keys SET active = 0 WHERE id = ? AND userId = ?').run(keyId, userId);
    return res.changes > 0;
  }

  validateApiKeyAndDeduct(apiKeyString: string, quantity: number = 1): User | null {
    const keyRow: any = this.db.prepare('SELECT * FROM api_keys WHERE key = ?').get(this.hashToken(apiKeyString));
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
      .map((r) => this.rowToDomainVerification(r)!);
  }

  getDomainVerification(userId: string, domain: string): DomainVerification | undefined {
    return this.rowToDomainVerification(
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

  // Records an explicit ownership/authorization ATTESTATION and marks the domain
  // verified. Unlike DNS/file proof this trusts the user's affirmation, so the
  // exact statement they agreed to is stored for the audit trail. Upserts so a
  // domain with no prior pending record can still be attested in one step.
  attestDomainOwnership(userId: string, domain: string, attestation: string): DomainVerification {
    const now = new Date().toISOString();
    const existing = this.getDomainVerification(userId, domain);
    if (!existing) {
      const id = 'dv_' + crypto.randomBytes(8).toString('hex');
      const token = crypto.randomBytes(16).toString('hex');
      this.db.prepare(
        'INSERT INTO domain_verifications (id, userId, domain, token, verified, createdAt, verifiedAt, method, attestation) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)'
      ).run(id, userId, domain, token, now, now, 'attestation', attestation);
    } else {
      this.db.prepare(
        'UPDATE domain_verifications SET verified = 1, verifiedAt = ?, method = ?, attestation = ? WHERE userId = ? AND domain = ?'
      ).run(now, 'attestation', attestation, userId, domain);
    }
    return this.getDomainVerification(userId, domain)!;
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

  markMonitoredScanned(id: string, lastScannedAt: string, nextScanAt: string): void {
    this.db.prepare('UPDATE monitored_targets SET lastScannedAt = ?, nextScanAt = ? WHERE id = ?')
      .run(lastScannedAt, nextScanAt, id);
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
