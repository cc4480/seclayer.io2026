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
| `APP_URL` | Public base URL (e.g. `https://seclayer.io`). Magic-link sign-in and Stripe redirect URLs are built from this trusted host, never the request `Host` header. |
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

### Do NOT set in production

- `DEV_SKIP_AUTH` — dev-only auto-login; hard-disabled when `NODE_ENV=production`.
- `SCAN_DEV_ALLOW_HOSTS` — dev-only SSRF escape hatch; hard-disabled in production.

## 3. Build & run

### Docker (recommended)

```bash
docker build -t seclayer .
docker run -d --name seclayer \
  -p 3000:3000 \
  -v seclayer-data:/data \
  -e NODE_ENV=production \
  -e APP_URL=https://your-host \
  -e RESEND_API_KEY=re_... \
  # optional: DEEPSEEK_API_KEY, STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET
  seclayer
```

The image is multi-stage (build → pruned runtime), runs `node dist/server.cjs`,
persists the DB on the `/data` volume, and has a `HEALTHCHECK` wired to the
endpoint below.

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

## 7. Pre-production checklist

- [ ] Required env vars set (`NODE_ENV`, `APP_URL`, `RESEND_API_KEY`); optional
      keys set for any feature you want live (AI reports, payments).
- [ ] `DB_PATH` points at a persistent volume that survives redeploys.
- [ ] Behind TLS + a proxy/load balancer (the app sets `trust proxy` and
      derives Secure cookies / client IP from `X-Forwarded-*` in production).
- [ ] Stripe webhook configured (if payments are enabled).
- [ ] `@seclayer/mcp` published (if you advertise the MCP integration).
- [ ] `npm audit` reviewed. Remaining advisories at time of writing are 2
      moderate in a transitive dep of the MCP SDK (`@hono/node-server`
      serve-static, Windows-only) that the stdio server does not exercise;
      fixing requires a breaking SDK downgrade, so it is intentionally deferred.
- [ ] One real Docker image build + smoke test in the target environment
      (CI builds the app and both test suites, but does not build the image).
- [ ] Note: the frontend is verified manually (browser) — there is no automated
      UI test suite in CI yet.
