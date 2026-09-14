// Apply the Postgres schema to the database named by DATABASE_URL, out of band.
//
// The app already applies server/pg/schema.sql on boot (PostgresDb.applySchema),
// so a normal deploy needs nothing here. This script exists for the two cases
// that boot doesn't cover:
//   1. CI: stand up a throwaway Postgres, apply the schema, then run the
//      adapter's integration tests against it (server/pg/pgDb.integration.test.ts,
//      which skip themselves unless DATABASE_URL is set).
//   2. Standing up a fresh database by hand before the app's first boot.
//
// It applies the same three pieces boot does: the domain schema (schema.sql,
// idempotent, advisory-locked) plus the two out-of-band tables (rate_limit_hits,
// scan_events) that boot ensures separately.
//
//   DATABASE_URL=postgres://user:pass@host:5432/db node --import tsx scripts/apply-pg-schema.ts
import pg from "pg";
import { PostgresDb } from "../server/pg/pgDb.js";
import type { PgPool } from "../server/pg/pgClient.js";

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error("DATABASE_URL is not set — nothing to apply. Set it to the target Postgres.");
  process.exit(1);
}

// Mirror createDb() in server/db.ts: managed Postgres requires TLS, a local one
// (localhost/127.0.0.1, e.g. a CI container) has none.
const isLocal = /localhost|127\.0\.0\.1/.test(DATABASE_URL);
const ssl = isLocal ? undefined : { rejectUnauthorized: false };

async function main(): Promise<void> {
  const pool = new pg.Pool({ connectionString: DATABASE_URL, ssl });
  const db = new PostgresDb(pool as unknown as PgPool);
  try {
    await db.applySchema();
    await db.ensureRateLimitSchema();
    await db.ensureScanEventSchema();
    console.log("[apply-pg-schema] schema applied (domain + rate_limit_hits + scan_events).");
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error("[apply-pg-schema] failed:", err?.message || err);
  process.exit(1);
});
