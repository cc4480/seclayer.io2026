# Scaling Seclayer to 10,000 concurrent users — readiness runbook

This is the ordered plan to take Seclayer from its current **single-instance
monolith** to a horizontally-scalable deployment. It is written against the real
codebase (file references are accurate as of this document).

The engineering is solid — DB-backed sessions, `trust proxy`, graceful shutdown
with WAL checkpoint, crash-recovery (`db.recoverStuckScans`), body-size caps,
security headers, the SSRF gate, credit-refund-on-failure. **This is a scale-out
migration, not a rewrite.**

---

## 1. Why one instance is the ceiling today

| Component | Current implementation | Why it caps scale |
|---|---|---|
| **Database** | `better-sqlite3`, local file, WAL (`server/db.ts`) | **The hard blocker.** SQLite is single-writer and *synchronous* — every query blocks the Node event loop, and a local file can't be shared, so you **cannot run more than one app instance.** |
| **Scan execution** | Runs in the web process — dashboard fire-and-forgets `processScanJob` (`server/routes/scans.ts:116`); MCP awaits `runDiagnostics` inline (`server/routes/mcp.ts:70`) | Each scan = minutes of CPU + hundreds of network calls + an `nmap` subprocess. One instance saturates at **~10–30 concurrent scans**, not thousands. |
| **Rate limiter** | Pluggable store, in-memory default (`server/rateLimit.ts`) | ✅ **Seam added** — now swappable to Redis via `setRateLimitStore`. Still in-memory until a Redis store is wired. |
| **Background workers** | `monitor`/`digest`/`backup` on `setInterval` | ✅ **Gated by `SECLAYER_ROLE`** (`server.ts`) so only `worker`/`all` roles run them — no more N× duplication. |
| **Process model** | One Node process, one core | No clustering. |

Realistic single-instance capacity: **hundreds** of concurrent dashboard users
and a **handful** of concurrent scans. For 10k users where even 2–5% scan
(= 200–500 concurrent scans), you're 1–2 orders of magnitude past that on the
scan tier alone.

---

## 2. Target architecture

```
                        ┌─────────────────┐
   internet ──▶ LB ──▶  │  web × N         │  (stateless, autoscaled)
                        │  SECLAYER_ROLE=web│  serve HTTP, enqueue scans
                        └────────┬─────────┘
                                 │ enqueue
                    ┌────────────▼────────────┐        ┌──────────────┐
                    │  Redis  (queue + rate   │        │  Postgres    │
                    │  limit + cache)         │        │  (managed,   │
                    └────────────┬────────────┘        │  pooled)     │
                                 │ dequeue              └──────▲───────┘
                        ┌────────▼─────────┐                   │
                        │  scan-worker × M │  ──────────────────┘
                        │  SECLAYER_ROLE=  │  run runDiagnostics, autoscale
                        │  worker          │  on queue depth
                        └──────────────────┘
```

Every tier scales independently. The web tier is stateless (sessions live in the
DB). Scan throughput scales by adding workers, decoupled from web traffic.

---

## 3. Migration steps, in order

### ✅ Step 0 — Done (shipped, no infra required)
- **Web/worker role split** (`SECLAYER_ROLE=web|worker|all`, default `all`).
  Gates the background workers + boot recovery so multiple web instances don't
  duplicate monitoring/digest/backups. `server/config.ts`, `server.ts`.
- **Pluggable rate-limit store** with a Redis-ready seam. `server/rateLimit.ts`.
- **Concurrent-scan cap** (`MAX_CONCURRENT_SCANS`, default 4) — bounds in-process
  scans so a burst can't exhaust the instance; excess scans wait in `queued`
  (crash-safe). `server/semaphore.ts`, `server/scanWorker.ts`. This is also the
  per-worker concurrency control Step 2's worker fleet reuses.

### 🔴 Step 1 — Postgres (THE GATE — nothing else scales until this is done)
Everything downstream depends on a shared, networked, async database.

1. Provision managed Postgres (Neon / RDS / Supabase) + a pooler
   (PgBouncer / RDS Proxy) so N instances don't exhaust connections.
2. Port the schema: `server/dbSchema.ts` (`runMigrations`) → SQL/DDL migrations
   (sqlite `TEXT/INTEGER` → pg `text/bigint/timestamptz/jsonb`; `AUTOINCREMENT`
   → identity; check the `CREATE TABLE IF NOT EXISTS` blocks).
3. Rewrite the data layer: `server/db.ts` is **synchronous** (`better-sqlite3`).
   `pg` is **async**, so `db.getUser()` etc. become `Promise`-returning. This is
   the big ripple — **every `db.*` call site becomes `await db.*`** across all
   routes (`server/routes/*`), workers (`server/*Worker.ts`), and ~the 506 tests.
   Mitigation: keep the `db` object's method names/return shapes identical so the
   diff is mechanical (`await` + async signatures), and lean on `tsc` to find
   every call site.
4. `server/dbMappers.ts` row-shape mappers mostly carry over (watch pg's native
   types vs sqlite's stringified ones — dates, booleans, JSON columns).
5. Connection pooling config: size the pool to `(pooler_max / instance_count)`.
6. Verify: the existing 506-test suite is the safety net — it must stay green
   against a real Postgres (run it in CI with a Postgres service container).

**Effort: the largest single item.** Needs a real Postgres to develop/test
against. Do it as a focused branch, not incrementally on `main`.

### 🟠 Step 2 — Scan queue + worker fleet (biggest scaling win for a scanner)
Scans must NOT run in the web process.

1. Add a queue: BullMQ (Redis) or SQS. Web enqueues a job `{ scanId }` instead of
   calling `processScanJob` in-process; the dashboard route already returns the
   `scanId` immediately (`routes/scans.ts`) — just replace the fire-and-forget
   call with an enqueue.
2. `server/scanWorker.ts`'s `makeProcessScanJob` becomes the queue consumer's
   handler, running only on `SECLAYER_ROLE=worker` instances.
3. Autoscale workers on **queue depth**. Each worker caps its own concurrency
   (e.g. 2–4 scans/worker given each scan's CPU+network+nmap cost).
4. The MCP inline-await path (`routes/mcp.ts`) also switches to enqueue + the
   existing async result polling (`seclayer_get_report`).
5. Keep `recoverStuckScans` as the crash-safety net (now on workers only).

### 🟡 Step 3 — Redis for rate limiting + cache
- Implement `RedisRateLimitStore` (the sorted-set sketch is in `rateLimit.ts`),
  wire it with `setRateLimitStore()` at boot when `REDIS_URL` is set.
- Optionally cache hot reads (public report views, user/session lookups).

### 🟡 Step 4 — Run the fleet
- Containerize (Dockerfile exists), run N stateless `web` + M `worker` instances
  on ECS / Cloud Run / Fly / K8s with autoscaling. `trust proxy` is already set.
- Node cluster (or one container per core) to use all cores per box.
- Managed Postgres snapshots replace the in-process `backupWorker`.

### 🟢 Step 5 — Harden & prove
- Per-user scan quotas + queue fairness (scans are expensive compute at arbitrary
  targets — a real cost/abuse vector at scale; the SSRF gate already exists).
- Observability: request latency, **queue depth**, DB pool saturation, scan
  duration, worker concurrency.
- **Load test** (k6 / Artillery) against a staging fleet to find the true ceiling
  and right-size autoscaling before committing to a number.

---

## 4. Capacity note on "10,000 at a time"

- **10k concurrent dashboard users** (small % scanning): achievable with Steps
  1 + 3 + 4 (Postgres + Redis + a handful of autoscaled web instances) — weeks.
- **10k concurrent _scans_**: a capacity/cost question once Step 2 exists. Each
  scan is minutes of work, so ~10k simultaneous ⇒ a large worker fleet
  (hundreds of cores) sized from the load test. The architecture supports it;
  the spend is the real constraint.

## 5. Effort summary

| Step | Unblocks | Infra needed | Size |
|---|---|---|---|
| 0 (role split, rate-limit seam) | multi-instance correctness | none | ✅ done |
| 1 Postgres | horizontal scaling at all | managed PG + pooler | **large** |
| 2 Queue + workers | scan throughput | Redis/SQS + worker service | large |
| 3 Redis rate-limit/cache | correct limits across fleet | Redis | small |
| 4 Fleet | actual capacity | container platform | medium |
| 5 Quotas + load test | confidence in the number | staging + k6 | medium |
