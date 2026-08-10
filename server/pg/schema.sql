-- Postgres schema for Seclayer — the translation of server/dbSchema.ts's
-- runMigrations() to Postgres DDL. Runs idempotently (every CREATE/ALTER uses
-- IF NOT EXISTS) so it's safe to apply on every boot, like the SQLite version.
--
-- TYPE-MAPPING DECISIONS (deliberately chosen to require ZERO changes to
-- server/dbMappers.ts — the same row shapes the app already expects):
--   * SQLite TEXT      -> text
--   * SQLite INTEGER   -> integer          (ids/counters; amounts/credits are small)
--   * booleans         -> integer 0/1      (NOT boolean) — the mappers already do
--                          `x === 1` / `x ? 1 : 0`, so keeping 0/1 avoids touching them
--   * timestamps       -> text (ISO-8601)  — the app stores/reads new Date().toISOString();
--                          keeping text avoids any Date<->timestamptz conversion in mappers
--   * JSON columns      -> text            — findings/evidence/narrationLog/executiveBreakdown/
--                          result/rawXml are JSON.stringify'd by the app; keeping text keeps
--                          the (de)serialization identical (upgrade to jsonb later if desired)
--
-- The adapter (a future server/pgDb.ts) is responsible for the OTHER pg
-- difference the schema doesn't cover: parameter placeholders are $1,$2,... in
-- pg, not ? as in better-sqlite3.

CREATE TABLE IF NOT EXISTS users (
  id             text PRIMARY KEY,
  email          text UNIQUE NOT NULL,
  credits        integer NOT NULL DEFAULT 0,
  createdAt      text NOT NULL,
  notifyWebhook  text,
  deepseekApiKey text,
  emailDigest    integer NOT NULL DEFAULT 0,
  lastDigestAt   text
);

CREATE TABLE IF NOT EXISTS scans (
  id                 text PRIMARY KEY,
  userId             text NOT NULL,
  url                text NOT NULL,
  authHeader         text,
  status             text NOT NULL,
  score              integer,
  severity           text,
  findings           text,
  aiSummary          text,
  error              text,
  createdAt          text NOT NULL,
  completedAt        text,
  aiReasoning        text,
  narrationLog       text,
  executiveBreakdown text,
  evidence           text,
  shareToken         text
);
CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(userId);
-- Nullable unique: Postgres (like SQLite) allows many NULLs in a UNIQUE index,
-- so only issued (non-null) share tokens must be unique.
CREATE UNIQUE INDEX IF NOT EXISTS idx_scans_share ON scans(shareToken);

CREATE TABLE IF NOT EXISTS transactions (
  id              text PRIMARY KEY,
  userId          text NOT NULL,
  amount          integer NOT NULL,
  type            text NOT NULL,
  stripeSessionId text,
  createdAt       text NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tx_user ON transactions(userId);

CREATE TABLE IF NOT EXISTS api_keys (
  id         text PRIMARY KEY,
  userId     text NOT NULL,
  key        text UNIQUE NOT NULL,
  credits    integer NOT NULL DEFAULT 0,
  active     integer NOT NULL DEFAULT 1,
  createdAt  text NOT NULL,
  keyPreview text
);
CREATE INDEX IF NOT EXISTS idx_keys_user ON api_keys(userId);

CREATE TABLE IF NOT EXISTS domain_verifications (
  id          text PRIMARY KEY,
  userId      text NOT NULL,
  domain      text NOT NULL,
  token       text NOT NULL,
  verified    integer NOT NULL DEFAULT 0,
  createdAt   text NOT NULL,
  verifiedAt  text,
  method      text,
  attestation text
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_domain_verif_user_domain ON domain_verifications(userId, domain);

CREATE TABLE IF NOT EXISTS suppressions (
  id           text PRIMARY KEY,
  userId       text NOT NULL,
  targetUrl    text NOT NULL,
  findingTitle text NOT NULL,
  reason       text,
  createdAt    text NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_supp_user ON suppressions(userId);

CREATE TABLE IF NOT EXISTS monitored_targets (
  id             text PRIMARY KEY,
  userId         text NOT NULL,
  url            text NOT NULL,
  frequencyDays  integer NOT NULL,
  scheduleString text,
  lastScannedAt  text,
  nextScanAt     text,
  createdAt      text NOT NULL,
  scanHour       integer,
  scanMinute     integer,
  scanWeekday    integer,
  lastError      text,
  paused         integer NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_mon_user ON monitored_targets(userId);

CREATE TABLE IF NOT EXISTS login_tokens (
  tokenHash  text PRIMARY KEY,
  email      text NOT NULL,
  expiresAt  text NOT NULL,
  consumedAt text,
  createdAt  text NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  tokenHash text PRIMARY KEY,
  userId    text NOT NULL,
  expiresAt text NOT NULL,
  createdAt text NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(userId);

CREATE TABLE IF NOT EXISTS oob_tokens (
  token     text PRIMARY KEY,
  scanId    text,
  createdAt text NOT NULL
);

CREATE TABLE IF NOT EXISTS oob_events (
  id         text PRIMARY KEY,
  token      text NOT NULL,
  method     text NOT NULL,
  sourceIp   text NOT NULL,
  path       text NOT NULL,
  userAgent  text,
  receivedAt text NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oob_events_token ON oob_events(token);

CREATE TABLE IF NOT EXISTS nmap_scans (
  id          text PRIMARY KEY,
  userId      text NOT NULL,
  url         text NOT NULL,
  resolvedIp  text,
  status      text NOT NULL,
  nmapVersion text,
  result      text,
  rawXml      text,
  error       text,
  createdAt   text NOT NULL,
  startedAt   text,
  completedAt text
);
CREATE INDEX IF NOT EXISTS idx_nmap_scans_user ON nmap_scans(userId);

CREATE TABLE IF NOT EXISTS autofix_sessions (
  id              text PRIMARY KEY,
  userId          text NOT NULL,
  targetUrl       text NOT NULL,
  findingTitle    text NOT NULL,
  findingCategory text NOT NULL,
  status          text NOT NULL,
  turns           integer NOT NULL DEFAULT 0,
  createdAt       text NOT NULL,
  updatedAt       text NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_autofix_sessions_user ON autofix_sessions(userId);

-- One-time data fix-up carried over from dbSchema.ts: revoke domains that were
-- ever trusted on self-attestation alone (that path was removed; real DNS/file
-- proof is required now). Idempotent.
UPDATE domain_verifications SET verified = 0 WHERE method = 'attestation';

-- NOTE (not expressible in pure DDL, handled by the adapter's migration step):
-- the legacy plaintext-API-key rewrite in dbSchema.ts (migrateLegacyPlaintextApiKeys)
-- must run once after this schema is applied — it re-hashes any api_keys.key still
-- in the raw "sl_live_<hex>" format. A fresh Postgres install has no such rows, but
-- a SQLite->Postgres data import would; run it as part of the import.
