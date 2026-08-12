# Deploying Seclayer

A single Node process serves both the API and the prebuilt React client. State
lives in a SQLite file that must be on a persistent volume. This is the
practical checklist for standing it up.

## 1. Prerequisites

- Node.js 22 (matches the Docker image and CI).
- A persistent volume for the SQLite database.
- The third-party keys below (email is mandatory in production; the rest gate
  optional features).

## 2. Environment variables

The app validates configuration at boot and **refuses to start in production**
if a production-critical value is missing (see `server/config.ts`).

### Required in production

| Variable | Purpose |
|---|---|
| `NODE_ENV=production` | Enables Secure cookies, HSTS, `trust proxy`, and serving the prebuilt `dist/` instead of the Vite dev server. |
| `APP_URL` | Public base URL (e.g. `https://seclayerio.ai`). Magic-link sign-in and Stripe redirect URLs are built from this trusted host, never the request `Host` header. |
| `RESEND_API_KEY` | Resend key for magic-link sign-in emails. Without it, production refuses to boot (users could never receive a login link). |

### Recommended / feature-gating (optional)

| Variable | Default / when unset | Purpose |
|---|---|---|
| `PORT` | `3000` | Listen port (most platforms inject this). |
| `DB_PATH` | `./data.sqlite` | SQLite file path. Point at the persistent volume (the Docker image uses `/data/seclayer.sqlite`). |
| `EMAIL_FROM` | `Seclayer <onboarding@resend.dev>` | Sender identity for outbound email. |
| `DEEPSEEK_API_KEY` | local summaries | Enables AI-written reports; falls back to built-in local summaries when unset. |
| `FREE_MODE` | on when Stripe unset | Free public testing: scans require no credits and the paywall is hidden. Defaults ON whenever Stripe isn't configured, OFF once it is. Set `FREE_MODE=false` to force paid mode, or `FREE_MODE=true` to keep it free even with Stripe configured. |
| `STRIPE_SECRET_KEY` + `STRIPE_WEBHOOK_SECRET` | purchases disabled | Enable real credit purchases via Stripe Checkout. Both must be set. Setting them also flips the `FREE_MODE` default to off. |
| `OOB_BASE_URL` | falls back to `APP_URL` | Base URL the *scanned target* can call back on for blind-SSRF proofs. Set only if it differs from `APP_URL`. |
| `NMAP_SCAN_TIMEOUT_MS` | `1800000` (30 min) | Hard timeout for a single Network Reconnaissance scan (see §7). Resource ceiling, not a scope limit. |
| `ALLOW_MISSING_EMAIL_PROVIDER` | off | Lets production boot without `RESEND_API_KEY`. Sign-in links are logged to the console AND returned directly in the login modal as a one-click "open sign-in link" button — no inbox or log-reading needed. Auth itself is unchanged (still a real, single-use, 15-minute token) — only safe on a private, single-operator instance (e.g. local Docker), since anyone who can reach the login form gets handed the token directly instead of it going to the target inbox. |

### Do NOT set in production

- `DEV_SKIP_AUTH` — dev-only auto-login; hard-disabled when `NODE_ENV=production`.
- `SCAN_DEV_ALLOW_HOSTS` — dev-only SSRF escape hatch; hard-disabled in production.

## 3. Build & run

### Docker (recommended)

**Via docker compose** (simplest — reads secrets from a `.env` file you
control, persists the DB on a named volume, and already passes the
`--cap-add` flags Network Reconnaissance needs — see §7):

```bash
cp .env.example .env   # fill in at least APP_URL + RESEND_API_KEY
docker compose up -d --build
```

No `RESEND_API_KEY` yet? For local-only use you can set
`ALLOW_MISSING_EMAIL_PROVIDER=true` in `.env` instead — the login modal then
shows an "open sign-in link" button directly, no email or log-reading needed
(see the table above).

**Via plain `docker run`:**

```bash
docker build -t seclayer .
docker run -d --name seclayer \
  -p 3000:3000 \
  -v seclayer-data:/data \
  -e NODE_ENV=production \
  -e APP_URL=https://your-host \
  -e RESEND_API_KEY=re_... \
  --cap-add=NET_ADMIN --cap-add=NET_RAW \
  # optional: DEEPSEEK_API_KEY, STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET
  # omit the two --cap-add flags if you don't need Network Reconnaissance
  seclayer
```

The image is multi-stage (build → pruned runtime), runs `node dist/server.cjs`,
persists the DB on the `/data` volume, and has a `HEALTHCHECK` wired to the
endpoint below.

### Railway

`railway.json` pins the Dockerfile builder and wires `/api/system/health` as
Railway's own healthcheck. Railway's builder does not support a Dockerfile
`VOLUME` instruction (rejects the build outright) — this repo's Dockerfile
intentionally omits it and relies on an attached Railway Volume instead, same
as the Docker/compose flows above already do with an explicit `-v`.

```bash
npx @railway/cli login          # opens a browser
npx @railway/cli init --name seclayer
npx @railway/cli up --ci --service seclayer      # first build (will crash-loop until env vars below are set — expected)
npx @railway/cli volume add -m /data             # persistent SQLite volume
npx @railway/cli domain                          # generates a *.up.railway.app URL
npx @railway/cli variable set "APP_URL=https://<the-generated-domain>" --skip-deploys
npx @railway/cli variable set "FREE_MODE=true" --skip-deploys   # or leave unset; defaults on without Stripe
echo -n "re_..." | npx @railway/cli variable set RESEND_API_KEY --stdin --skip-deploys
echo -n "sk-..." | npx @railway/cli variable set DEEPSEEK_API_KEY --stdin --skip-deploys
npx @railway/cli redeploy --yes
npx @railway/cli service source connect --repo <owner>/<repo> --branch main   # auto-deploy on future pushes
```

Note: on Git Bash (Windows), a leading `/` in `--mount-path`/`-m` gets
silently mangled into a Windows path by MSYS's path conversion, which then
fails with "Mount path must start with a `/`" — prefix the `volume add`
command with `MSYS_NO_PATHCONV=1` if you hit that.

Network Reconnaissance (nmap) needs `--cap-add=NET_ADMIN`/`NET_RAW`, which
Railway's runtime doesn't expose — the feature auto-disables cleanly there
(§7), same as on any host without those capabilities.

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

## 7. Network Reconnaissance (nmap) — optional, self-hosted only

Nmap ships baked into the Docker image (installed + `setcap` in the
Dockerfile — see its comments). The app probes for the binary once at boot
and cleanly hides the whole feature (no error, no partial UI) whenever it
isn't present or runnable — which is always the case on Railway, a
Vercel-hosted deployment, or any local `npm run dev` checkout without nmap
installed manually. Needs the `--cap-add` flags in §3 to actually work, which
means a VPS running the Docker/compose flow directly, or another platform that
exposes custom container capabilities.

- **Requires `--cap-add=NET_ADMIN --cap-add=NET_RAW` on every `docker run`
  (or the equivalent in compose/Kubernetes)** — confirmed by booting the
  built image with and without these flags. `setcap` in the Dockerfile
  scopes the capability to the nmap binary itself (least privilege — the
  Node process doesn't get it), but a binary's file capabilities can never
  exceed the container's own capability bounding set, and Docker's default
  set includes `NET_RAW` but **not** `NET_ADMIN`. Without both flags, nmap
  fails to even exec (`spawn EPERM`) and the feature silently stays
  detected-absent — this is not limited to hardened `--cap-drop=ALL` setups,
  it's the default-Docker behavior. `docker-compose.yml` already sets both;
  the plain `docker run` example in §3 does too.
- **Without those capabilities at all**, the whole binary fails to exec
  rather than degrading — the two flags above are required, not optional,
  whenever this feature should be live.
- Same domain-ownership verification gate as every other active probe (DNS
  TXT record or well-known file) — no separate authorization step to
  configure.
- Verify it's live: the console UI's "Network Reconnaissance" card only
  renders when the backend reports the feature available (`nmapAvailable` on
  `GET /api/auth/me`); if it's silently absent, check the boot log for
  `[config] nmap ... — Network Reconnaissance is disabled on this deployment.`

## 8. Pre-production checklist

- [ ] Required env vars set (`NODE_ENV`, `APP_URL`, `RESEND_API_KEY`); optional
      keys set for any feature you want live (AI reports, payments).
- [ ] `DB_PATH` points at a persistent volume that survives redeploys.
- [ ] Database backups: automated `VACUUM INTO` snapshots run on a cadence
      (default daily, keeping 7) to `BACKUP_DIR` (defaults next to `DB_PATH`).
      Point `BACKUP_DIR` at durable storage and/or copy snapshots off-box
      (they are single self-contained files); set `BACKUP_ENABLED=false` to
      opt out.
- [ ] Behind TLS + a proxy/load balancer (the app sets `trust proxy` and
      derives Secure cookies / client IP from `X-Forwarded-*` in production).
- [ ] Stripe webhook configured (if payments are enabled).
- [ ] `@seclayer/mcp` published (if you advertise the MCP integration).
- [ ] If advertising Network Reconnaissance, confirm `--cap-add=NET_ADMIN
      --cap-add=NET_RAW` is set (see §7), the boot log shows nmap detected,
      and that a real scan against a target you own completes.
- [ ] `npm audit` reviewed — clean at time of writing (0 advisories).
- [ ] One real Docker image build + smoke test in the target environment
      (CI builds the app and both test suites, but does not build the image).
- [ ] Note: the frontend is verified manually (browser) — there is no automated
      UI test suite in CI yet.
