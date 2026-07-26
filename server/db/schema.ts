// Schema creation + additive migrations, applied on every boot (all idempotent).
// Schema changes are additive column migrations rather than destructive
// rewrites, so an existing database upgrades in place.
import type Database from 'better-sqlite3';
import { hashToken, maskKey } from './util.js';

const LEGACY_RAW_KEY_PATTERN = /^sl_live_[0-9a-f]{32}$/;

function addColumnIfMissing(db: Database.Database, table: string, column: string, decl: string) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  if (!cols.some((c) => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${decl}`);
  }
}

// One-time (idempotent) upgrade: earlier versions stored API keys in plaintext
// in api_keys.key. Rewrite any row still in the raw "sl_live_<32 hex>" format to
// store only its SHA-256 hash plus a display-safe preview, so a database read
// alone can never yield a usable key.
function migrateLegacyPlaintextApiKeys(db: Database.Database) {
  const rows = db.prepare('SELECT id, key FROM api_keys').all() as Array<{ id: string; key: string }>;
  for (const row of rows) {
    if (LEGACY_RAW_KEY_PATTERN.test(row.key)) {
      db.prepare('UPDATE api_keys SET key = ?, keyPreview = ? WHERE id = ?')
        .run(hashToken(row.key), maskKey(row.key), row.id);
    }
  }
}

export function runMigrations(db: Database.Database) {
  db.exec(`
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
    CREATE TABLE IF NOT EXISTS oob_tokens (
      token TEXT PRIMARY KEY,
      scanId TEXT,
      createdAt TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS oob_events (
      id TEXT PRIMARY KEY,
      token TEXT NOT NULL,
      method TEXT NOT NULL,
      sourceIp TEXT NOT NULL,
      path TEXT NOT NULL,
      userAgent TEXT,
      receivedAt TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_oob_events_token ON oob_events(token);
  `);
  // Additive column migrations (safe across existing databases).
  addColumnIfMissing(db, "users", "notifyWebhook", "TEXT");
  addColumnIfMissing(db, "api_keys", "keyPreview", "TEXT");
  addColumnIfMissing(db, "scans", "aiReasoning", "TEXT");
  addColumnIfMissing(db, "scans", "narrationLog", "TEXT");
  addColumnIfMissing(db, "scans", "executiveBreakdown", "TEXT");
  addColumnIfMissing(db, "scans", "evidence", "TEXT");
  addColumnIfMissing(db, "domain_verifications", "method", "TEXT");
  addColumnIfMissing(db, "domain_verifications", "attestation", "TEXT");
  addColumnIfMissing(db, "monitored_targets", "scanHour", "INTEGER");
  addColumnIfMissing(db, "monitored_targets", "scanMinute", "INTEGER");
  addColumnIfMissing(db, "monitored_targets", "scanWeekday", "INTEGER");
  migrateLegacyPlaintextApiKeys(db);
}
