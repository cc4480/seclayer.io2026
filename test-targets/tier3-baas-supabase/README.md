# Tier 3 — Supabase BaaS Test Fixture

Real local Supabase stack (Postgres + RLS, PostgREST, GoTrue Auth, Realtime,
Storage, Edge Functions — via the Supabase CLI's Docker-based local dev
environment, no paid cloud account needed) plus a thin Express proxy app,
with 9 genuinely vulnerable endpoints and 4 negative controls (see
`vulnerabilities.json`), adapted from
`~/Downloads/vulnapps/TIER3_BAAS_SUPABASE_PRD.md`. Same approach as Tiers 1–2:
real infrastructure and real code, not simulated responses, built to verify
what Seclayer's actual scanner detects. **Local use only — never expose this
to the internet.**

Several vulnerabilities are adapted from the PRD's specific technical claims,
which don't hold up against the real, hardened Supabase engine (same
discipline as Tier 2's JWT `alg:none` adaptation) — see each vulnerability's
`adaptationNote` in `vulnerabilities.json` and the comments in
`supabase/migrations/00000000000001_tier3_schema.sql` and the route files.
The short version: the PRD's "RLS fails open on NULL" claim is incorrect
(Postgres RLS is fail-closed on NULL), and literal `../` path traversal
against Supabase Storage doesn't work against the real engine — both were
rebuilt around the realistic, common real-world version of the same class of
bug (a backend route using the SERVICE ROLE key, which bypasses RLS by
design, without checking who's actually asking).

## Prerequisites

- Docker Desktop running, with a reasonable amount of memory allocated (the
  full stack — Postgres, Kong, GoTrue, PostgREST, Realtime, Storage, Edge
  Functions — fits in ~2GB once `analytics`/`studio`/`local_smtp` are
  disabled in `supabase/config.toml` as they are here; less than ~3GB total
  Docker memory risks health-check timeouts on `storage`/`realtime` under
  load)
- Supabase CLI (`npx supabase`, no install needed)
- Node 20.6+ (uses `node --env-file`)

## Set up and run

```bash
cd test-targets/tier3-baas-supabase
npx supabase start          # first run pulls several GB of images — be patient
npx supabase status -o env  # prints SUPABASE_URL / ANON_KEY / SERVICE_ROLE_KEY / JWT_SECRET / DB URL
```

Create `.env` in this directory (never committed — see `.gitignore`) with the
values `supabase status` printed:

```
SUPABASE_URL=http://127.0.0.1:54321
SUPABASE_ANON_KEY=<ANON_KEY from supabase status>
SUPABASE_SERVICE_ROLE_KEY=<SERVICE_ROLE_KEY from supabase status>
SUPABASE_JWT_SECRET=<JWT_SECRET from supabase status>
# Same value as SUPABASE_JWT_SECRET, under a name the CLI's env(...)
# resolution doesn't skip (it silently ignores SUPABASE_-prefixed vars) — see
# [edge_runtime.secrets] in config.toml, needed for sensitive-task-safe.
TIER3_JWT_SECRET=<same value as SUPABASE_JWT_SECRET>
DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:54322/postgres
PORT=4103
```

Also paste the real `SUPABASE_ANON_KEY` into `public/index.html` in place of
the placeholder (this is the planted exposure for T3-AnonKey-Abuse-001 — it
needs to be a real, working key for the vulnerability to be real, not just
illustrative). If you change the local JWT secret from the CLI's fixed dev
default, restart the stack (`npx supabase stop && npx supabase start`) before
re-seeding — `edge_runtime.secrets` and PostgREST's schema/grants cache are
only picked up on (re)start.

```bash
npm install
node --env-file=.env scripts/seed.mjs   # creates alice/bob via real GoTrue signup, seeds rows
npm start                               # listens on 127.0.0.1:4103
```

`scripts/seed.mjs` retries each step once after a short pause — right after
`supabase db reset`/`start`, PostgREST's schema/grants cache can be briefly
stale, causing the first request or two to 403 with "permission denied" even
though the grant is correct. This is a startup race, not a real gap; see the
comment in the script.

## Scan it with Seclayer

1. Add this app's port to `SCAN_DEV_ALLOW_HOSTS` in the main repo's
   `.env.local`: `127.0.0.1:4103` (and `127.0.0.1:54321` if scanning the raw
   Supabase API directly for T3-AnonKey-Abuse-001/T3-EdgeFunc-001).
2. `npm run dev` in the repo root.
3. `scripts/seed.mjs`'s output prints alice's and bob's real access tokens —
   use alice's as `authHeader`. Two-identity BOLA (`bolaIdentities`, own file
   path per identity) for T3-Storage-001 is driven through the engine's
   `bolaIdentities` option (the MCP `seclayer_scan` tool doesn't expose it yet)
   — confirmed detecting against the live route this way (see
   `vulnerabilities.json`).

## Expected / actual results

`vulnerabilities.json`'s `actualResult`/`notes` fields on each entry are the
real, observed outcome — not a prediction. Final tally, after investigating
every gap ("find out why, then fix it" — same discipline as Tier 1/2):
**8/9 detected with real evidence (6 of those via new detection capabilities,
1 via fixing a real product bug, 1 via the existing two-identity BOLA probe),
1/9 confirmed non-reproducible on the modern platform (not a scanner gap).**

| ID | Result | Notes |
|---|---|---|
| T3-RLS-Bypass-001 (`/api/profiles`) | ✅ **Detected** (new capability) | New `exposedUserListInCapture()` in `server/apiProbes.ts` — flags a crawled JSON array of 2+ distinct user records reachable with no auth. Wired into the existing passive crawl-capture loop. |
| T3-VectorDB-Injection-001 (`/api/search`) | ✅ **Detected** (after a fix) | The real `pg` driver's raw syntax-error text (`unterminated quoted string at or near "..."`, `syntax error at or near "..."`) matched neither the wrapped-driver nor SQLite patterns already in `SQL_ERROR_SIGNATURE` — same bug class as the Tier 1 SQLite fix, now for Postgres. Fixed in `server/redTeam/sqlInjection.ts` + `server/paramFuzzer.ts`. |
| T3-Backup-Exposure-001 (`/backups/*.sql`) | ✅ **Detected** (new capability) | New `analyzeDataDumpExposure()` in `server/staticAnalysis.ts` — signature-matches real pg_dump/mysqldump boilerplate on any crawled response, regardless of content-type. |
| T3-JWT-Secret-001 (`.env` leak → forge → bypass) | ✅ **Detected** (new capability) | Both halves now caught: the `.env` leak (`Exposed Critical Resource File`) AND the forge-and-bypass itself (`JWT Signature Not Verified (leaked-secret-resign)`) — a validly-signed forged token, proven via a real 401-vs-200 differential against `/api/profiles-safe`. New `extractJwtSecretCandidates()` + a `leaked-secret-resign` forgery variant in `server/jwtProbe.ts`. Getting this to fire live also required broadening `probeJwtAuth`'s candidate-path list beyond its fixed guess-list (`/api/admin`, `/api/me`, ...) to include crawl-discovered URLs — this app's real protected route, `/api/profiles-safe`, doesn't look like any of the guesses. |
| T3-Realtime-Hijack-001 | ⚪ **Does not reproduce** — not a gap | Empirically confirmed on a real local Realtime server: RLS is enforced on `postgres_changes` by default now. Alice reliably receives her own updates, never Bob's. Same "hardened since the PRD was written" pattern as Tier 2's JWT `alg:none`. |
| T3-AnonKey-Abuse-001 | ✅ **Detected** (new capability) | New `server/credentialChainProbe.ts`: pairs a same-prefix URL+key declared in the same served content (`window.SUPABASE_URL`/`window.SUPABASE_ANON_KEY`), then tests that key directly against the *other* origin it names — proven via a real, unauthenticated read of `admin_config` at the raw Supabase REST origin. Reuses `safeFetch`'s existing SSRF gate; the target origin is one the scanned app's own content named, never a guess. |
| T3-EdgeFunc-001 | ✅ **Detected** (new capability) | New `server/edgeFunctionProbe.ts` — extracts the function URL from the app's OWN client content (`.../functions/v1/<name>` / `functions.invoke('<name>')` + a discovered base URL, never guessed), then proves the bypass with a read-only GET differential (no token → 401, forged token → 200 with the exported secret). Same cross-origin "act on what the content names" principle as the credential-chain probe. |
| T3-Unlogged-001 (`/api/tokens`) | ✅ **Detected** (new capability) | New `exposedCredentialListInCapture()` in `server/apiProbes.ts` — a sibling to the user-list check for the *credential*-dump shape. Fires only on a JSON array of 2+ records where every element pairs a user identifier with a distinct credential-shaped value (`token`/`api_key`/`secret`/...), so it stays low-FP where matching a bare `"token"` field alone would not. |
| T3-Storage-001 | ✅ **Detected** (existing capability, now confirmed) | Driven the real two-identity probe (`server/bola.ts`) against the live `/api/files/:ownerId/:filename` route — surfaces as **Unauthenticated Access to Protected Resource** (PROVEN), the honest/stronger label since the route enforces no auth at all. Same confirmation path as T1-IDOR-001 / T2-HorzPrivEsc-001. Note: reachable via the engine's `bolaIdentities`, which the MCP scan tool doesn't yet expose. |
