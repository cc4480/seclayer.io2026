# Deploying Seclayer

A Node process (or several — the app is multi-replica-safe, see below) serves
both the API and the prebuilt React client. **Production state lives in
Postgres** (`DATABASE_URL`); the app refuses to boot in
`NODE_ENV=production` without it (see `server/db.ts`). SQLite (`DB_PATH`) is
the fallback for local dev, tests, and a deliberate single-node deploy only.
This is the practical checklist for standing it up.

## 1. Prerequisites

- Node.js 22 (matches the Docker image and CI).
- A Postgres database (Railway Postgres, Supabase, or any Postgres 13+)
  reachable via `DATABASE_URL`. Schema is applied automatically at boot from
  `server/pg/schema.sql` — no manual migration step for a fresh database.
  (Only skip this and use the SQLite fallback if you genuinely want a
  single-node, non-`production` deploy — then you need a persistent volume
  for the SQLite file instead.)
- The third-party keys below (email is mandatory in production; the rest gate
  optional features).

## 2. Environment variables

The app validates configuration at boot and **refuses to start in production**
if a production-critical value is missing (see `server/config.ts`).

### Required in production

| Variable | Purpose |
|---|---|
| `NODE_ENV=production` | Enables Secure cookies, HSTS, `trust proxy`, and serving the prebuilt `dist/` instead of the Vite dev server. |
| `APP_URL` | Public base URL (e.g. `https://seclayer.app`). Sign-in and Stripe redirect URLs are built from this trusted host, never the request `Host` header. |
| `DATABASE_URL` | Postgres connection string. Production **refuses to boot** without it — the SQLite fallback would otherwise serve an empty, ephemeral database and look healthy while doing it (`server/db.ts`, `assertNotSilentlyFallingBack`). Schema self-applies at boot; multi-replica safe (a transaction-scoped advisory lock serializes concurrent boots). |
| `RESEND_API_KEY` | Resend key for sign-in emails (one-time code, not a link). Without it, production refuses to boot (users could never receive a code). |

### Recommended / feature-gating (optional)

| Variable | Default / when unset | Purpose |
|---|---|---|
| `PORT` | `3000` | Listen port (most platforms inject this). |
| `DB_PATH` | `./data.sqlite` | SQLite file path, used only when `DATABASE_URL` is unset (local dev / single-node fallback). Point at a persistent volume if you deploy this way (the Docker image uses `/data/seclayer.sqlite`). |
| `EMAIL_FROM` | `Seclayer <onboarding@resend.dev>` | Sender identity for outbound email. |
| `DEEPSEEK_API_KEY` | local summaries | Enables AI-written reports; falls back to built-in local summaries when unset. |
| `ENCRYPTION_KEY` | BYO-key storage disabled | 32-byte base64 key (AES-256-GCM) that seals a user's own DeepSeek API key at rest. A user's key is a live billable third-party credential, so without this the endpoint refuses to store one (503) rather than writing cleartext to the `users` table. Rows written before this existed are read as plaintext and re-sealed the next time the user saves. Generate with `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`; rotating it invalidates stored keys (users re-enter them). |
| `FREE_MODE` | on when Stripe unset | Free public testing: scans require no credits and the paywall is hidden. Defaults ON whenever Stripe isn't configured, OFF once it is. Set `FREE_MODE=false` to force paid mode, or `FREE_MODE=true` to keep it free even with Stripe configured. |
| `STRIPE_SECRET_KEY` + `STRIPE_WEBHOOK_SECRET` | purchases disabled | Enable real credit purchases via Stripe Checkout. Both must be set. Setting them also flips the `FREE_MODE` default to off. |
| `OOB_BASE_URL` | falls back to `APP_URL` | Base URL the *scanned target* can call back on for blind-SSRF proofs. Set only if it differs from `APP_URL`. |
| `ENABLE_BROWSER_RENDERING` | off | `true` renders SPAs with headless Chromium during the crawl, surfacing client-rendered links and XHR endpoints static parsing cannot see. |
| `ENABLE_TARGET_SCREENSHOT` | off | `true` captures the target's landing page and shows it on the report's Overview tab. A **separate** flag from the one above, on purpose: a landing-page visual is much cheaper than a full JS crawl. Chromium ships in the image either way, so neither flag needs anything installed — but with both unset the browser is dead weight. Unset produces no screenshot and no error. |
| `NMAP_SCAN_TIMEOUT_MS` | `1800000` (30 min) | Hard timeout for a single Network Reconnaissance scan (see §7). Resource ceiling, not a scope limit. |
| `ALLOW_MISSING_EMAIL_PROVIDER` | off | Lets production boot without `RESEND_API_KEY`. The sign-in code is logged to the console AND returned directly to the login modal, which displays it inline ("Dev mode — your code is ...") — no inbox or log-reading needed. Auth itself is unchanged (still a real, single-use, 10-minute 6-digit code) — only safe on a private, single-operator instance (e.g. local Docker), since anyone who can reach the login form gets handed the code directly instead of it going to the target inbox. |

### Do NOT set in production

- `DEV_SKIP_AUTH` — dev-only auto-login; hard-disabled when `NODE_ENV=production`.
- `SCAN_DEV_ALLOW_HOSTS` — dev-only SSRF escape hatch; hard-disabled in production.

## 3. Build & run

### Docker (recommended)

**Via docker compose** (simplest — reads secrets from a `.env` file you
control, persists the DB on a named volume, and passes the `NET_RAW`
capability that upgrades Network Reconnaissance to full SYN + OS scans — see §7):

```bash
cp .env.example .env   # fill in at least APP_URL + RESEND_API_KEY + DATABASE_URL
docker compose up -d --build
```

The image runs `NODE_ENV=production`, so it needs a real `DATABASE_URL`
(Postgres) — it will not silently fall back to SQLite. For a local-only,
single-node run without Postgres, set `NODE_ENV=development` in `.env`
instead; data then persists to the SQLite file on the `seclayer-data` volume.

No `RESEND_API_KEY` yet? You can set `ALLOW_MISSING_EMAIL_PROVIDER=true` in
`.env` instead — the login modal then displays the sign-in code inline, no
email or log-reading needed (see the table above).

**Via plain `docker run`:**

```bash
docker build -t seclayer .
docker run -d --name seclayer \
  -p 3000:3000 \
  -e NODE_ENV=production \
  -e APP_URL=https://your-host \
  -e RESEND_API_KEY=re_... \
  -e DATABASE_URL=postgres://user:pass@host:5432/seclayer \
  --cap-add=NET_RAW \
  # optional: DEEPSEEK_API_KEY, STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET
  # --cap-add=NET_RAW upgrades Network Reconnaissance to SYN + OS scans; it is
  # already in Docker's default set, so you can omit it and nmap still runs a
  # TCP connect scan (no OS detection). NET_ADMIN is not needed.
  seclayer
```

The image is multi-stage (build → pruned runtime) and runs `node
dist/server.cjs`, with a `HEALTHCHECK` wired to the endpoint below. State
lives in the Postgres database above, not in the container — no volume is
needed for `DATABASE_URL` deploys. Running without `DATABASE_URL` instead
(`-e NODE_ENV=development`, single-node only) needs `-v seclayer-data:/data`
to persist the SQLite file across restarts.

### Railway

There is no `railway.json` in this repo (one existed briefly but was never
actually applied — Railway reported `railwayConfigFile: null` — and was
deleted; see "Railway configuration" below). Build/deploy settings — builder,
healthcheck path, replica count — are set on the service itself, in the
Railway dashboard or via `railway api`, not from a file here. Railway's
builder also does not support a Dockerfile `VOLUME` instruction (rejects the
build outright); this repo's Dockerfile intentionally omits it.

Add a Railway Postgres to the project first (**Postgres is what production
actually runs on** — see the top of this file):

```bash
npx @railway/cli login          # opens a browser
npx @railway/cli init --name seclayer
npx @railway/cli add --database postgres         # provisions a Postgres service in this project
npx @railway/cli up --ci --service seclayer      # first build (will crash-loop until env vars below are set — expected)
npx @railway/cli domain                          # generates a *.up.railway.app URL
npx @railway/cli variable set "APP_URL=https://<the-generated-domain>" --skip-deploys
npx @railway/cli variable set "FREE_MODE=true" --skip-deploys   # or leave unset; defaults on without Stripe
echo -n "re_..." | npx @railway/cli variable set RESEND_API_KEY --stdin --skip-deploys
echo -n "sk-..." | npx @railway/cli variable set DEEPSEEK_API_KEY --stdin --skip-deploys
npx @railway/cli redeploy --yes
npx @railway/cli service source connect --repo <owner>/<repo> --branch main   # auto-deploy on future pushes
```

Set `DATABASE_URL` on the `seclayer` service to the Postgres service's
connection string — in the dashboard's Variables tab, reference it as
`${{Postgres.DATABASE_URL}}` (confirm the exact reference variable name under
the Postgres service's own Variables tab; it is not necessarily set
automatically just by both services existing in the same project).

Once `DATABASE_URL` is set, schema applies itself on boot (`server/pg/schema.sql`)
— nothing to migrate by hand for a fresh database, and it's safe across
however many replicas boot at once (a transaction-scoped advisory lock
serializes them). This is also what makes the service safe to scale to
multiple replicas (see "Railway configuration" below) — SQLite on a Railway
Volume cannot be shared across replicas at all.

Deploying single-node on SQLite instead is still possible (skip the Postgres
step, don't set `DATABASE_URL`, and keep `NODE_ENV` off `production` — or see
`server/db.ts` if you genuinely want a production single-node SQLite deploy).
That path needs a persistent volume:

```bash
npx @railway/cli volume add -m /data             # persistent SQLite volume
```

Note: on Git Bash (Windows), a leading `/` in `--mount-path`/`-m` gets
silently mangled into a Windows path by MSYS's path conversion, which then
fails with "Mount path must start with a `/`" — prefix the `volume add`
command with `MSYS_NO_PATHCONV=1` if you hit that.

Network Reconnaissance (nmap) works on Railway in unprivileged mode: Railway's
runtime strips `CAP_NET_RAW`, so the app detects that at boot and runs a TCP
connect scan (service/version + NSE `vuln` scripts, no SYN stealth or OS
detection) instead of disabling the feature (§7). Hosts that expose `NET_RAW`
(compose/`docker run` above, a VPS) get the full SYN + OS-detection scan.

### Without Docker

```bash
npm ci
npm run build              # vite build + esbuild bundle -> dist/
NODE_ENV=production APP_URL=https://your-host RESEND_API_KEY=re_... node dist/server.cjs
```

## 4. Verify it's up

```bash
curl -fsS https://your-host/api/system/health
# {"status":"Online","version":"...","timestamp":"..."}
```

On boot the server also recovers any scans left mid-flight by a prior
crash/redeploy (marks them failed and refunds the credit).

## 5. Stripe webhook (only if payments are enabled)

Point a Stripe webhook at `POST /api/webhooks/stripe` for the
`checkout.session.completed` event and set `STRIPE_WEBHOOK_SECRET` to its
signing secret. Credits are granted only by this verified webhook, never by the
checkout call itself. Delivery is idempotent (retries never double-grant).

## 6. MCP server (`@seclayer/mcp`)

The stdio MCP server the dashboard advertises lives in `mcp-server/`. To make
`npx -y @seclayer/mcp` work for users, publish it (requires npm credentials for
the `@seclayer` org, from a machine that is `npm login`'d):

```bash
cd mcp-server
npm publish            # prepublishOnly runs the build; ships dist/ + README only
```

Users then add it to their agent (get the key from the dashboard's Developer
API Keys panel):

```bash
claude mcp add seclayer -- npx -y @seclayer/mcp --key YOUR_API_KEY
# Cursor / Windsurf: add an MCP server, command: npx -y @seclayer/mcp --key YOUR_API_KEY
```

Override the backend with `--url` / `SECLAYER_API_URL` for self-hosted installs.

## 7. Network Reconnaissance (nmap) — optional, self-hosted + Railway

Nmap ships baked into the Docker image (installed in the Dockerfile — see its
comments). The image sets **no** file capabilities on the binary and runs as
root, so nmap always execs; the app probes once at boot both for the binary and
for whether raw sockets actually work in this container, then picks the scan
technique accordingly. It cleanly hides the whole feature (no error, no partial
UI) only when the binary is genuinely absent — e.g. a Vercel-hosted deployment
or a bare local `npm run dev` checkout without nmap installed.

- **Two modes, chosen automatically at boot:**
  - **Privileged (full)** — when the container's capability bounding set
    includes `CAP_NET_RAW` (a normal `docker run`/compose, a VPS): root nmap
    opens raw sockets natively and runs the default SYN scan plus OS detection
    (`-sV -O`). No `setcap` and no `--cap-add` are strictly required (NET_RAW is
    in Docker's default set), but `docker-compose.yml` / the §3 `docker run`
    example pin `--cap-add=NET_RAW` to make it explicit and survive hardened
    `--cap-drop` bases.
  - **Unprivileged (connect scan)** — when the platform strips `CAP_NET_RAW`
    (e.g. **Railway**, which doesn't let you add caps back): the boot probe
    detects raw sockets are unavailable and the scan runs `-sT --unprivileged`
    (TCP connect + service/version + NSE `vuln` scripts, **no** OS detection).
    Still useful port/service/vuln recon — the feature is live, just without SYN
    stealth and OS fingerprinting.
- **`CAP_NET_ADMIN` is NOT used.** The earlier build put `net_admin` in the
  binary's effective file-cap set via `setcap`; because a file cap that exceeds
  the container's bounding set makes the kernel refuse to even exec the binary
  (`spawn EPERM`), that silently killed the feature on Railway (and any
  `docker run` without `--cap-add=NET_ADMIN`). Removing the file caps fixed it.
- Same domain-ownership verification gate as every other active probe (DNS
  TXT record or well-known file) — no separate authorization step to
  configure.
- Verify it's live: the console UI's "Network Reconnaissance" card only
  renders when the backend reports the feature available (`nmapAvailable` on
  `GET /api/auth/me`). The boot log states which mode is active:
  `[config] nmap <ver> detected — Network Reconnaissance is available
  (privileged: … | unprivileged: …).`

## 8. Pre-production checklist

- [ ] Required env vars set (`NODE_ENV`, `APP_URL`, `RESEND_API_KEY`,
      `DATABASE_URL`); optional keys set for any feature you want live (AI
      reports, payments).
- [ ] Database backups: with `DATABASE_URL` set, the app's own SQLite
      snapshotter turns itself off (it would only be backing up a stale,
      unused file) — backups are the Postgres provider's job instead (e.g.
      Railway Postgres PITR, or `pg_dump`). Confirm PITR/backups are actually
      enabled on the database, not just assumed. *(Only relevant if you're
      deliberately running the SQLite fallback: automated `VACUUM INTO`
      snapshots then run on a cadence — default daily, keeping 7 — to
      `BACKUP_DIR`, which should point at durable, off-box storage; set
      `BACKUP_ENABLED=false` to opt out, and `DB_PATH` must point at a
      persistent volume that survives redeploys.)*
- [ ] Behind TLS + a proxy/load balancer (the app sets `trust proxy` and
      derives Secure cookies / client IP from `X-Forwarded-*` in production).
- [ ] Stripe webhook configured (if payments are enabled).
- [ ] `@seclayer/mcp` published (if you advertise the MCP integration).
- [ ] If advertising Network Reconnaissance, confirm the boot log shows nmap
      detected (§7) and a real scan against a target you own completes. For the
      full SYN + OS-detection scan, ensure `CAP_NET_RAW` is available
      (`--cap-add=NET_RAW`); without it the scan still runs in connect-scan mode.
- [ ] `npm audit` reviewed — clean at time of writing (0 advisories).
- [ ] One real Docker image build + smoke test in the target environment
      (CI builds the app and both test suites, but does not build the image).
- [ ] Note: the frontend is verified manually (browser) — there is no automated
      UI test suite in CI yet.

## Railway configuration

Set on the service itself, not from a file in this repo.

There used to be a `railway.json` here. It was never applied — the Railway API
reported `railwayConfigFile: null` and every setting it declared disagreed with
what was actually running (it asked for the `DOCKERFILE` builder and a
`/api/system/health` healthcheck; the live service was on `RAILPACK` with no
healthcheck at all). Railway also deprecated that format, with existing files
stopping work on 2026-12-01, so it was removed rather than migrated: there was
no behaviour to carry across.

Change build and deploy settings in the Railway dashboard under
Service -> Settings, or with `railway api` against `serviceInstanceUpdate`, and
verify the change took rather than assuming — that is the same lesson the
config file taught the expensive way.
