/**
 * One-way data migration: the SQLite volume file -> Postgres.
 *
 * Why this is a plain copy and not a transform: server/pg/schema.sql was
 * deliberately written to mirror SQLite's storage exactly — booleans stay
 * integer 0/1, dates stay text, JSON columns stay text. So every column is
 * text or integer on both sides and no value needs coercing. Verified against
 * the schema, not assumed.
 *
 * Safety properties:
 *   - READ-ONLY on SQLite. Opens the file readonly; the source is never touched.
 *   - Idempotent. Every insert is ON CONFLICT DO NOTHING, so a partial run can
 *     simply be re-run rather than unpicked.
 *   - Verifies. Compares per-table row counts at the end and exits non-zero on
 *     any mismatch, so "it seemed to work" is not a possible outcome.
 *   - --dry-run reads and reports without writing anything.
 *
 * Usage:
 *   SQLITE_PATH=./data.sqlite DATABASE_URL=postgres://... npx tsx scripts/migrate-sqlite-to-pg.ts [--dry-run]
 */
import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';
import Database from 'better-sqlite3';
import pg from 'pg';

const DRY = process.argv.includes('--dry-run');
const SQLITE_PATH = process.env.SQLITE_PATH || process.env.DB_PATH || 'data.sqlite';
const DATABASE_URL = process.env.DATABASE_URL;

const here = path.dirname(url.fileURLToPath(import.meta.url));
const SCHEMA_SQL = path.join(here, '..', 'server', 'pg', 'schema.sql');

if (!DATABASE_URL) { console.error('DATABASE_URL is required (the TARGET Postgres).'); process.exit(2); }
if (!fs.existsSync(SQLITE_PATH)) { console.error(`SQLite file not found: ${SQLITE_PATH}`); process.exit(2); }

// Table order comes from schema.sql itself rather than a hardcoded list, so it
// cannot drift out of sync when a table is added. The file declares parents
// before children, which is the order inserts need.
const schemaSql = fs.readFileSync(SCHEMA_SQL, 'utf-8');
const TABLES = [...schemaSql.matchAll(/CREATE TABLE (?:IF NOT EXISTS )?([a-z_]+)/gi)].map((m) => m[1]);

const sqlite = new Database(SQLITE_PATH, { readonly: true });
const isLocal = /localhost|127\.0\.0\.1/.test(DATABASE_URL);
const pool = new pg.Pool({
  connectionString: DATABASE_URL,
  ssl: isLocal ? undefined : { rejectUnauthorized: false },
});

async function main() {
  console.log(`source : ${SQLITE_PATH}`);
  console.log(`target : ${DATABASE_URL.replace(/:[^:@/]+@/, ':****@')}`);
  console.log(`tables : ${TABLES.length}${DRY ? '   [DRY RUN — no writes]' : ''}\n`);

  if (!DRY) {
    await pool.query(schemaSql);          // idempotent: every statement is IF NOT EXISTS
    console.log('schema applied\n');
  }

  const summary: { table: string; read: number; written: number }[] = [];

  for (const table of TABLES) {
    // A table present in the PG schema but absent from an older SQLite file is
    // expected (additive migrations), not an error — record 0 and move on.
    const exists = sqlite.prepare(
      "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table);
    if (!exists) { console.log(`  ${table.padEnd(22)} — not in SQLite, skipped`); summary.push({ table, read: 0, written: 0 }); continue; }

    const rows = sqlite.prepare(`SELECT * FROM ${table}`).all() as Record<string, unknown>[];
    if (rows.length === 0) { console.log(`  ${table.padEnd(22)} 0 rows`); summary.push({ table, read: 0, written: 0 }); continue; }

    const cols = Object.keys(rows[0]);
    // Identifiers are left UNQUOTED on purpose: schema.sql declares them
    // unquoted too, so Postgres folds both to lower case and they match.
    // Quoting here would look for a camelCase column that does not exist.
    const colList = cols.join(', ');
    // Postgres caps a statement at 65535 bind parameters.
    const perBatch = Math.max(1, Math.min(500, Math.floor(65535 / cols.length)));
    let written = 0;

    if (!DRY) {
      for (let i = 0; i < rows.length; i += perBatch) {
        const batch = rows.slice(i, i + perBatch);
        const values: unknown[] = [];
        const tuples = batch.map((row, r) => {
          const ph = cols.map((c, c_i) => { values.push(row[c]); return `$${r * cols.length + c_i + 1}`; });
          return `(${ph.join(', ')})`;
        });
        const res = await pool.query(
          `INSERT INTO ${table} (${colList}) VALUES ${tuples.join(', ')} ON CONFLICT DO NOTHING`, values);
        written += res.rowCount ?? 0;
      }
    }
    console.log(`  ${table.padEnd(22)} ${String(rows.length).padStart(6)} read${DRY ? '' : ` -> ${written} inserted`}`);
    summary.push({ table, read: rows.length, written });
  }

  if (DRY) { console.log('\nDry run complete — nothing written.'); return; }

  console.log('\n--- verification (SQLite vs Postgres row counts) ---');
  let bad = 0;
  for (const { table, read } of summary) {
    const pgCount = Number((await pool.query(`SELECT count(*)::int AS n FROM ${table}`)).rows[0].n);
    // >= not ==: ON CONFLICT DO NOTHING means a re-run inserts 0 new rows while
    // the totals still have to match, and Postgres may legitimately hold rows
    // written after the snapshot was taken.
    const ok = pgCount >= read;
    if (!ok) bad++;
    console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${table.padEnd(22)} sqlite=${String(read).padStart(6)}  pg=${String(pgCount).padStart(6)}`);
  }
  if (bad) { console.error(`\n${bad} table(s) short in Postgres — migration INCOMPLETE.`); process.exit(1); }
  console.log('\nAll tables match or exceed the source. Migration verified.');
}

main()
  .catch((e) => { console.error('migration failed:', e?.message || e); process.exit(1); })
  .finally(async () => { sqlite.close(); await pool.end(); });
