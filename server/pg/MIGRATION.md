# SQLite → Postgres migration (in progress, branch: `postgres-migration`)

Postgres is the gate to horizontal scaling (see `/SCALING.md`): SQLite is a
single-writer local file that can't be shared across instances, and
`better-sqlite3` is synchronous (blocks the event loop). Moving to Postgres
means the data layer becomes **async** (there is no synchronous Postgres client
for Node), which ripples through every `db.*` call site.

## Done on this branch (safe, verifiable without a live Postgres)
- **`server/pg/schema.sql`** — the full schema translated to Postgres DDL,
  idempotent (every `CREATE`/`ALTER` uses `IF NOT EXISTS`). **Type mapping is
  deliberately chosen to require ZERO row-mapper changes**: booleans stay
  `integer` 0/1, timestamps stay `text` (ISO strings), JSON stays `text` — the
  exact shapes `server/dbMappers.ts` already produces/consumes.
- **`server/pg/pgParams.ts` (`toPositional`)** — converts `?` placeholders to
  `$1,$2,…` (quote-aware). This lets the adapter **reuse the exact SQL strings
  from `server/db.ts` verbatim** instead of hand-rewriting 115 queries — the
  single biggest source of adapter risk, removed. Unit-tested.
- **`server/pg/pgRowCase.ts` (`normalizeRow`)** — resolves a real trap:
  Postgres folds unquoted identifiers to lower case, so `SELECT *` returns
  `createdat`/`userid`/`aisummary`, but `server/dbMappers.ts` reads camelCase
  (`row.createdAt`, …) → every camelCase field would silently be `undefined`.
  The adapter runs each row through `normalizeRow` before the mappers; SQLite is
  unaffected, so the mappers stay identical for both backends. Unit-tested,
  including a test that a real pg-shaped row feeds `rowToUser`/`rowToScan`
  correctly. **This is exactly the class of bug a mock-pg test would NOT catch —
  concrete proof the adapter body must be validated against a real Postgres.**

## Remaining — needs a live Postgres to build + validate responsibly
A `DATABASE_URL` connection string (a free Neon/Supabase instance is enough) is
required for these, so the adapter and the async conversion can be validated
against a real database rather than shipped as unverified code.

1. **Add `pg`** (+ `@types/pg`) as a dependency.

2. **Define the async `Database` interface** — the ~115 method signatures from
   `db.ts`, each returning a `Promise`. Both backends implement it.

3. **Write `server/pgDb.ts` (`PostgresDb`)** implementing that interface. Reuse
   each SQL string from `SqliteDb` piped through `toPositional`, executed via a
   pooled client. Map `.get()`→`rows[0]`, `.all()`→`rows`, `.run()`→`await`.
   Transactions (`getOrCreateUser`, `addCredits`, …) become a pooled client with
   `BEGIN`/`COMMIT`/`ROLLBACK`.

4. **Make `SqliteDb` async too** (so both satisfy the interface and every call
   site is identical regardless of backend). `better-sqlite3` stays synchronous
   under the hood; the methods just become `async` (return `Promise`). This is
   what lets the **existing 506-test suite validate the entire async conversion
   on in-memory SQLite**, before Postgres is even wired.

5. **Convert the ~560 `db.*` call sites to `await`** (147 app + 417 test). Drive
   it with `tsc` — once the interface is async, every un-awaited use that reads a
   property errors, giving the complete worklist. **The one class tsc will NOT
   catch: a missed `await` in a truthiness context** (`if (db.getUser(id))` — a
   Promise is always truthy). These are security-relevant (auth/credit checks),
   so audit them explicitly:
   `grep -rnE '(if \(|!|\?\?|\|\||&&|return |assert[^(]*\() *db\.' server` and
   confirm each has an `await`.

6. **Select the backend at boot**: `export const db = process.env.DATABASE_URL ?
   new PostgresDb(...) : new SqliteDb(...)`. Run `schema.sql` on `PostgresDb`
   init (like `runMigrations` today), then `migrateLegacyPlaintextApiKeys`.

7. **Validate**: run the full suite against Postgres in CI (a `postgres` service
   container) as well as SQLite. Add a pooler (PgBouncer/RDS Proxy) for the fleet.

## Data migration (existing prod data)
A one-shot exporter reads every table from the SQLite file and bulk-inserts into
Postgres (shapes are identical, so it's a straight copy), then runs
`migrateLegacyPlaintextApiKeys` on the imported `api_keys`.
