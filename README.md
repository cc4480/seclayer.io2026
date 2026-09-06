# Seclayer

> **Repository identity.** This repo (`seclayer.io2026`) is **Seclayer**,
> deployed at **seclayer.app** on the Railway project `seclayer-app`.
>
> It is **not** SecScan. SecScan is a separate product in a separate repo
> (`VibeScan-Enterprise-Build`, deployed at secscan.us) with no shared git
> history. Seclayer is the higher tier: everything SecScan does, plus real
> nmap port/service scanning and the red-team attack modules in
> `server/redTeam/`. Data lives in SQLite on a Railway volume
> (`DB_PATH=/data/seclayer.sqlite`), not Postgres.
>
> The two launch separately. Never deploy one to the other's Railway service.

Pay-Per-Scan black-box penetration testing SaaS with an MCP scan endpoint.

Seclayer runs real black-box checks against a target URL, then enriches the
results with a DeepSeek-generated executive report and a posture score. Every
finding is mapped to its OWASP Top 10 (2021) category, and detections are
signature-confirmed for high precision (low false positives).

**Scan coverage**

- Security headers, TLS, and cookie flags
- Exposed-secret signatures + vulnerable JavaScript library detection
- DNS/subdomain recon and signature-confirmed sensitive-path probing
- **Crawler + parameter discovery** — maps links, forms, and JS-referenced API
  endpoints, then fuzzes the parameters the app actually uses
- Active SQLi / XSS / command-injection / SSRF / GraphQL / object-level-auth probes
  — gated behind domain-ownership verification (DNS TXT record or well-known
  file); unverified targets still get the full passive recon pass above
- **Template engine** — data-driven detections (exposed panels, actuators,
  config/backup files); grow coverage by adding templates, no code changes
- **Authenticated scans** — Bearer/Basic/Cookie/custom-header credentials applied
  across the whole request surface
- **Optional headless rendering** (Playwright) for SPA/JS-heavy targets
- **Continuous monitoring** with scheduled re-scans and Slack-compatible alerts
- **Auto-fix PRs** — `@seclayer/mcp autofix` runs an AI agent inside your own
  CI job to fix each proven, high-confidence finding and opens a pull request;
  no separate AI key, and your source never leaves the CI runner (see
  [mcp-server/README.md](mcp-server/README.md#auto-fix-prs-seclayer-mcp-autofix))

## Stack

- **Frontend:** React 19 + Vite 6 + Tailwind 4
- **Backend:** Express 4 (TypeScript via tsx), better-sqlite3
- **Auth:** passwordless magic-link sign-in with httpOnly session cookies; MCP
  API keys are shown once at creation and stored only as a SHA-256 hash
- **AI:** DeepSeek (OpenAI-compatible API), with local fallback summaries
- **Email:** Resend (magic links); console fallback in dev
- **Payments:** Stripe Checkout + signed webhooks

## Run locally

**Prerequisites:** Node.js 22+

```bash
npm install
cp .env.example .env.local   # optional: configure keys
npm run dev                  # http://localhost:3000
```

With no keys set, the app still runs: AI uses local summaries, magic-link URLs
are printed to the server console (and returned to the dev UI), and credit
purchases are disabled.

## Scripts

- `npm run dev` — server + Vite dev middleware
- `npm run lint` — TypeScript typecheck (`tsc --noEmit`)
- `npm test` — unit tests (Node test runner)
- `npm run build` — build client + bundle server to `dist/`
- `npm start` — run the production build

## Configuration

See [.env.example](.env.example). Key variables:

| Variable | Purpose |
|----------|---------|
| `NODE_ENV` | `production` enables Secure cookies, HSTS, trust-proxy, static serving |
| `PORT` | Listen port (default 3000) |
| `APP_URL` | Public base URL (magic-link + checkout redirect URLs) |
| `DB_PATH` | SQLite file path (default `./data.sqlite`) |
| `ENABLE_BROWSER_RENDERING` | `true` to crawl SPAs via headless Playwright (opt-in; install Playwright separately) |
| `DEEPSEEK_API_KEY` | Enables AI reports (else local summaries) |
| `RESEND_API_KEY` / `EMAIL_FROM` | Sends magic-link emails (else console) |
| `STRIPE_SECRET_KEY` / `STRIPE_WEBHOOK_SECRET` | Enables credit purchases |

Point your Stripe webhook at `POST /api/webhooks/stripe`
(`checkout.session.completed`). Credits are granted only on a verified webhook.

## Deployment

```bash
docker build -t seclayer .
docker run -p 3000:3000 --env-file .env.local -v seclayer-data:/data seclayer
```

The container exposes a `/api/system/health` healthcheck and stores its SQLite
database on the `/data` volume. CI (`.github/workflows/ci.yml`) runs typecheck,
tests, and build on every push.
