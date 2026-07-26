// Data layer entry point. Opens the single SQLite connection (WAL), runs
// migrations, and composes the per-domain repository modules into one flat `db`
// object — preserving the exact `db.method(...)` surface every caller and test
// uses, while each domain's SQL lives in its own <200-line module under db/.
import path from 'path';
import Database from 'better-sqlite3';
import { scoreFindings } from './scoring.js';
import { runMigrations } from './db/schema.js';
import { makeAccountsRepo } from './db/accounts.js';
import { makeScansRepo } from './db/scans.js';
import { makeApiKeysRepo } from './db/apiKeys.js';
import { makeDomainsRepo } from './db/domains.js';
import { makeSuppressionsRepo } from './db/suppressions.js';
import { makeMonitoringRepo } from './db/monitoring.js';
import { makeReadModel } from './db/readModel.js';

export { cleanUrl } from './db/util.js';
// Re-exported for callers/tests that recompute a score from a finding set.
export const recalculateScore = scoreFindings;

const DB_FILE = process.env.DB_PATH || path.join(process.cwd(), 'data.sqlite');

const sql = new Database(DB_FILE);
sql.pragma('journal_mode = WAL');
sql.pragma('foreign_keys = ON');
runMigrations(sql);

const accounts = makeAccountsRepo(sql);
const scans = makeScansRepo(sql);
const apiKeys = makeApiKeysRepo(sql, accounts);
const domains = makeDomainsRepo(sql);
const suppressions = makeSuppressionsRepo(sql);
const monitoring = makeMonitoringRepo(sql);
const readModel = makeReadModel(suppressions);

// The single flat data API. `db.db` exposes the raw connection for the few
// call sites (and tests) that need direct SQL.
export const db = {
  db: sql,
  ...accounts,
  ...scans,
  ...apiKeys,
  ...domains,
  ...suppressions,
  ...monitoring,
  ...readModel,
};
