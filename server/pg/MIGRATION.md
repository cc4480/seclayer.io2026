# SQLite → Postgres migration

**Status: COMPLETE and merged.** The data layer is now async and runs on either
backend behind one `Db` contract. Prod stays on SQLite until `DATABASE_URL` is
set (see "Production cutover" below) — the switch is a single env var, opt-in.

Validation: `tsc` clean; the full suite is green on SQLite (531 pass / 2 gated
skips); the Postgres adapter passed a full-breadth + concurrency integration
test against a live Supabase (`pgDb.integration.test.ts`, run with
`DATABASE_URL` set).

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

- **`server/pg/pgClient.ts` + `server/pg/pgDb.ts` (`PostgresDb`)** — the adapter
  infrastructure (get/all/run helpers, async-native BEGIN/COMMIT/ROLLBACK
  transaction helper) + the mock-tested critical core (auth/sessions, users,
  credits, scans, api-key validation, health). Reuses SqliteDb's SQL verbatim via
  `toPositional` + `normalizeRow`. **Mock-tested 7/7** (correct `$n` SQL, params,
  camelCase mapping, transaction sequencing, rollback). The remaining SqliteDb
  methods follow the identical pattern.

## What shipped
- **`pg` + `@types/pg`** added as dependencies.
- **`SqliteDb` is now async** — every method returns a `Promise`; `better-sqlite3`
  stays synchronous under the hood (bodies run inline, then resolve). Transaction
  bodies never `await`, preserving atomicity (see below).
- **`Db` contract** = the public surface of `SqliteDb` (`export type Db =
  Pick<SqliteDb, keyof SqliteDb>`); `PostgresDb implements Db`, so `tsc` verifies
  the two backends match exactly — no hand-maintained interface to drift.
- **`PostgresDb`** reuses each `SqliteDb` SQL string verbatim via `toPositional`
  (`?`→`$n`) + `normalizeRow` (pg lower-case → camelCase), over a pooled client.
- **~535 `db.*` call sites converted to `await`** (app + tests) via an AST codemod
  (`db.foo()` → `(await db.foo())`, enclosing fn marked `async`), then the
  residue fixed by hand: helper fns that became async (`isCanceled`,
  `activeProbesUnlocked`, `runBackup`, `keyOwner`, `completedScan`) + their
  callers; `OobStore`/`issue()` made async; three `.map(async …)` sites that
  silently produced `Promise[]` wrapped in `await Promise.all(...)`.
- **Backend selector** (`server/db.ts` `createDb()`): `DATABASE_URL` set → Postgres
  (TLS on, pooled), else SQLite. Chosen once at import.
- **Atomicity preserved across the async boundary** (money + cancellation paths):
  - `deductCredits` / `validateApiKeyAndDeduct`: SQLite runs the check-and-debit
    in one **synchronous** transaction (no `await` yields between read and write);
    Postgres uses `SELECT … FOR UPDATE` row-locking. Both proven by a concurrent
    "one credit, N racers, exactly one wins" test (SQLite in `scans.test.ts`,
    Postgres in `pgDb.integration.test.ts`).
  - `updateScan` / `updateNmapScan` guard terminal writes with `AND status !=
    'canceled'`, so a late worker write can never clobber a user's cancellation
    (the async `isCanceled()` check-then-write gap can't cover this alone).

## Remaining — production cutover (a deliberate, explicit step)
The code is merged and prod runs on SQLite. To move prod to Postgres:
1. **Migrate existing prod data** (if any is worth keeping): a one-shot exporter
   reads every table from the live SQLite file and bulk-inserts into Postgres
   (shapes are identical → straight copy), then runs
   `migrateLegacyPlaintextApiKeys` on the imported `api_keys`. The prod SQLite
   file lives on the Railway volume, so this runs on Railway (or against a pulled
   copy). **Skip only if starting fresh is acceptable.**
2. **Apply `server/pg/schema.sql`** to the target database (already done on the
   current Supabase instance: 13 tables).
3. **Set `DATABASE_URL`** as a Railway variable → next deploy switches the backend.
4. **Fleet later**: add a pooler (Supabase transaction pooler needs care — it
   breaks explicit `BEGIN`/`COMMIT`; use the session pooler or a real pool) and
   set `SECLAYER_ROLE`/`MAX_CONCURRENT_SCANS` per the scale-out plan.
