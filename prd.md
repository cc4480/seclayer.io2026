# Seclayer — Product Requirements Document

Pay-per-scan black-box penetration testing, built so every finding is directly actionable — by the person reading it, and by the AI coding agent they hand it to.

**Status:** Live product, actively evolving
**Doc version:** 1.0
**Scope:** Current implementation + near-term roadmap

---

## Contents

1. [Overview & Vision](#01--overview--vision)
2. [Goals & Non-Goals](#02--goals--non-goals)
3. [Personas](#03--personas)
4. [Core User Flows](#04--core-user-flows)
5. [Functional Requirements](#05--functional-requirements)
   - [5.1 Auth & Accounts](#51-authentication--accounts)
   - [5.2 Scanning Engine](#52-scanning-engine)
   - [5.3 Domain Ownership Verification](#53-domain-ownership-verification)
   - [5.4 AI-Generated Reporting](#54-ai-generated-reporting)
   - [5.5 Findings Lifecycle](#55-findings-lifecycle)
   - [5.6 Continuous Monitoring](#56-continuous-monitoring)
   - [5.7 Monetization](#57-monetization)
   - [5.8 Developer / MCP Surface](#58-developer--mcp-surface)
   - [5.9 Reporting UI](#59-reporting-ui)
6. [Non-Functional Requirements](#06--non-functional-requirements)
7. [System Architecture](#07--system-architecture)
8. [Success Metrics](#08--success-metrics)
9. [Risks & Open Questions](#09--risks--open-questions)
10. [Out of Scope / Future Considerations](#10--out-of-scope--future-considerations)

---

## 01 — Overview & Vision

### What Seclayer is

Seclayer is a pay-per-scan security testing product: point it at a public URL and it runs real black-box checks — not a checklist, actual HTTP probes, DNS lookups, and (once ownership is proven) live exploit attempts — then compiles the results into a report a developer can act on immediately, with an MCP endpoint so an AI agent can act on it just as immediately.

The reason this exists: most teams either skip security testing entirely (too slow, too expensive, needs a specialist) or bolt on a scanner that produces a wall of theoretical findings nobody trusts. Seclayer's bet is precision and actionability over coverage-for-its-own-sake — every finding is signature-confirmed to keep false positives low, and every finding ships with three things a generic scanner doesn't: a plain-English impact statement, a fix tailored to the detected stack, and a ready-to-paste prompt for the reader's own AI coding agent.

The product already reflects a specific point of view: development teams increasingly work through AI coding agents (Cursor, Claude Code, Windsurf), so a security report's real destination is often not a human reading a PDF — it's a prompt window. Seclayer is built for that handoff.

---

## 02 — Goals & Non-Goals

### Goals

- **Low false-positive black-box coverage** across seven AppSec categories (SAST, DAST, IAST, SCA, EASM, RED_TEAM, API_SEC), each confirmed by a real signature match rather than a status code alone.
- **Actionable by default** — every finding carries an impact statement, a concrete fix, and an agent-ready remediation prompt, whether or not an AI key is configured.
- **Abuse-resistant by design** — active exploitation only runs once the caller proves they own the target, so the platform can't be turned into an anonymous attack proxy.
- **Dual-surface** — the same scanning core serves a human dashboard and a machine-callable MCP endpoint, with parity in output quality.
- **Frictionless trial** — the app is fully usable with zero configuration: no AI key, no email provider, and no payment processor all degrade to local, deterministic behavior rather than blocking use.

### Non-goals (current version)

- Multi-seat team/organization accounts — the account model is single user per email.
- Authenticated multi-step crawling (e.g. following a login form) — auth is a single supplied header applied to every request, not a session the crawler negotiates itself.
- Compliance report templates (SOC 2, PCI-DSS mappings) — findings map to OWASP Top 10 only.
- On-prem or self-hosted enterprise packaging.
- A human-pentester-in-the-loop review step.

---

## 03 — Personas

**Solo Dev Sam** *(primary)*
Indie hacker shipping a side project. Wants a quick, honest posture check before launching — no security background, no patience for a 40-page PDF of theoretical issues.

**Agent-Native Ana** *(primary)*
Engineer who lives in Cursor or Claude Code. Wants scan findings to arrive as something she can paste straight into her coding agent, not something she has to translate herself.

**Automation Alex** *(secondary)*
Building their own tool or CI pipeline. Talks to Seclayer exclusively through the MCP endpoint and an API key — never sees the dashboard.

**Compliance-Curious Chris** *(secondary)*
Runs a client site or small SaaS and wants standing coverage — continuous monitoring with a Slack alert the moment something regresses.

---

## 04 — Core User Flows

1. **Sign in.** Passwordless magic link by email; a fresh account lands on the dashboard with 5 free credits and no pre-provisioned API key.
2. **Launch a scan.** Enter a URL (optionally an auth header for gated apps) and watch a live progress feed narrated from the scan's real findings as they happen, not a scripted animation.
3. **Read the report.** An executive breakdown up top (summary, grouped risk themes, business impact, ranked priorities), then per-finding detail with impact, fix, a copyable agent prompt, and raw evidence where relevant. False positives can be suppressed inline.
4. **Prove ownership, unlock depth.** Add a DNS TXT record or well-known file; the next scan of that domain runs active exploit probes instead of passive recon only.
5. **Set up monitoring.** Pick a re-scan cadence and a webhook; get pinged only when something actionable shows up.
6. **Go machine-native.** Generate an API key (shown once), point an AI coding agent or CI job at the MCP endpoint, and get the same report quality back as JSON.
7. **Buy more credits.** Stripe Checkout when the balance runs low; credits land only after a verified payment webhook, never on checkout click.

---

## 05 — Functional Requirements

Organized by subsystem. Each requirement reflects current, shipped behavior unless marked **[planned]**.

### 5.1 Authentication & Accounts

**Sign-in.** Passwordless magic-link email sign-in. In local/dev use with no email provider configured, the link is logged to the console and returned to the UI instead of silently failing.

**Session security.**
- Sessions and magic-link tokens are random secrets; only their SHA-256 hash is ever persisted.
- Session cookie is httpOnly, Secure in production, SameSite=Lax, 30-day expiry.
- Magic-link tokens are single-use with a 15-minute expiry.

**New account defaults.** 5 free scan credits on signup. No API key is created automatically — a key's raw value can only ever be shown once, at the moment it's generated, so provisioning one before the user asks for it would mean it could never be displayed.

### 5.2 Scanning Engine

Every scan runs the applicable checks below against the target and any same-origin surface the crawler discovers. Findings are signature-confirmed — a probe only fires a finding when the response body actually matches an expected pattern, not merely on a status code, which is what keeps single-page apps (which return 200 for everything) from flooding reports with false positives.

| Category | What it checks |
|---|---|
| EASM | DNS resolution, authoritative nameserver, subdomain enumeration (33 common names, wildcard-DNS aware), leaked server/framework signatures. |
| IAST | Security header presence (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) and cookie flags (HttpOnly, Secure, SameSite). |
| SAST | Exposed-secret signatures in served HTML/JS — live Stripe keys, GitHub OAuth tokens, PEM private key blocks, AWS access keys, Google API keys — each confidence-rated by how likely it is to be a real leak. |
| SCA | Known-vulnerable JS library versions detected in served markup (jQuery, Bootstrap, AngularJS, Lodash), mapped to their CVEs. |
| DAST | Sensitive-path probing (`.env`, `.git/config`, `.git/HEAD`, `phpinfo.php`, `.aws/credentials`, `config.json`) plus a crawler that maps links, forms and JS-referenced endpoints, then fuzzes the parameters the app actually uses. API-first testing extends this: it discovers an OpenAPI/Swagger schema (at the usual well-known paths, or one you supply) and fuzzes every declared operation's query and JSON/form-body parameters through the same injection engine — reads under active probing, state-changing operations only under the aggressive opt-in. Same-origin enforced. |
| RED_TEAM | Active SQLi, reflected-XSS, OS command-injection, and SSRF probes — both against the root URL and against parameters the crawler discovered. Also a weak-session-token probe: when the caller supplies real login credentials for a target they own, the scanner logs in once and tries to reproduce the resulting token offline from common weak `hash(seed)` recipes — an exact match is proof, not a statistical guess (chosen deliberately over generic entropy testing, which cannot distinguish a hash of a weak seed from a real random token). |
| API_SEC | GraphQL introspection exposure and a broken-object-level-authorization (BOLA/IDOR) probe against a common enumerated-resource pattern. |
| Templates | A data-driven detection pack — exposed admin panels, actuators, config/backup files, `.htpasswd`, subdomain-takeover fingerprints, WordPress user enumeration, leaked `.netrc` — gated by the target's detected tech stack and extensible with no code changes. |

**Also applies everywhere.** SSRF protection blocks loopback, RFC1918, link-local, cloud-metadata, and CGNAT ranges plus internal hostnames — re-validated on every redirect hop, and applied identically to scan targets, alert webhooks, and ownership-verification checks. Authenticated scanning (a user-supplied Bearer/Basic/Cookie/custom header) is applied across every request the scan makes, not just the first one.

### 5.3 Domain Ownership Verification

Active exploitation (RED_TEAM, API_SEC, and parameter fuzzing) is gated behind proof that the caller owns the target domain — otherwise the platform itself becomes a way to anonymously attack someone else's site. Passive recon (headers, TLS, DNS, secrets, libraries, exposed files, surface mapping) always runs regardless.

- **DNS TXT record** at `_seclayer-challenge.<domain>` containing a server-issued token, *or*
- **Well-known file** at `/.well-known/seclayer-verification.txt` containing the same token.

An unverified scan always includes an explicit info-level finding disclosing that active probing was skipped and why — the gate is never silent.

### 5.4 AI-Generated Reporting

**deepseek-v4-pro — deep report.** Thinking mode, high reasoning effort. Rewrites every finding with an attacker's-eye description, a stack-tailored fix, a plain-English impact line, and a ready-to-paste agent prompt. Also produces the adjusted score, the headline executive summary, and a structured breakdown: risk themes, business impact, ranked priority actions.

**deepseek-v4-flash — live narration.** Non-thinking, low-latency. Narrates the scan's progress in two real bursts — after diagnostics, after analysis — built from the same data the report uses, never scripted filler.

Every AI-authored field has a deterministic, data-driven local fallback, so the product is fully functional with no AI key configured — degraded polish, never degraded function. The score shown anywhere in the product is always the deterministic severity-weighted calculation, never the model's own subjective figure, so narration and report can never disagree with each other.

### 5.5 Findings Lifecycle

A finding can be marked a false positive with a reason; suppression is applied as a read-time transform against the stored scan rather than rewriting it, so the original scan record is never mutated and the score recalculates live. Scoring itself runs through one shared weights table (critical/high/medium/low/info) used identically at scan time and at every later recalculation, so the number never drifts between the two.

### 5.6 Continuous Monitoring

A monitored target re-scans on a chosen cadence. Each re-scan re-validates safety (catches a target that has since started resolving to an internal address) and re-checks the credit balance, deferring rather than retrying a target it can't currently scan. A Slack-compatible webhook fires only when the result is actually actionable — an active high or critical finding — not on every completed scan.

### 5.7 Monetization

Credits are the unit of value: one credit buys one scan, spent identically whether it's launched from the dashboard, a monitor tick, or the MCP endpoint. Three Stripe packs are offered (single scan, 5-pack, 20-pack); credits are granted only by a signature-verified, idempotent Stripe webhook — never at checkout creation — so a webhook replay can't double-grant and a client-side redirect can't grant at all.

### 5.8 Developer / MCP Surface

A synchronous `POST /api/mcp/scan` endpoint authenticates by API key, runs the full diagnostic-and-AI pipeline in one call, and returns the same report quality as the dashboard — score, severity, executive breakdown, and per-finding impact/fix/agent-prompt — so an AI agent gets a first-class result, not a stripped-down one. Keys are shown in full exactly once, at creation; the server stores only a hash and a masked preview from then on.

**Auto-fix PRs.** The published `@seclayer/mcp` CLI's `autofix` subcommand (backed by `POST /api/mcp/autofix/start` and `/turn`) closes the loop past a copyable prompt: for each finding that's proven or high-confidence, it drives a DeepSeek-backed agent loop — proxied through the backend and billed through the same API-key credits, no separate AI key required — that reads and edits files and opens a pull request with the fix. Every filesystem read, edit, and test run executes inside the caller's own CI job; the backend only ever exchanges a message transcript and tool-call results, never source code. The agent's tool surface is deliberately minimal (file read/edit plus one operator-fixed test command, no arbitrary shell) since finding data can include content pulled from the scanned target's own responses. Always opens a PR, never merges — one branch per finding, capped by a configurable limit. Ships as a second, higher-privilege composite Action (`seclayer-autofix`, requiring `contents: write` + `pull-requests: write`) separate from the read-only scan-gate action.

### 5.9 Reporting UI

Findings are organized into category tabs with live counts and severity badges. Every finding carries its impact statement, its fix, a one-click "fix with AI" prompt, and — for API findings — the raw request/response evidence. The executive tab surfaces the AI's summary, an optional chain-of-thought trace, and the full structured breakdown, with PDF export and a shareable link.

---

## 06 — Non-Functional Requirements

**Security.** SSRF hardening on every outbound request that originates from user input. Every persisted secret (sessions, magic links, API keys) is hashed, never stored raw. Strict security headers on every response, including errors. Error responses are structured JSON only — no stack traces leak to the client.

**Resilience.** A single scan's failure marks that scan failed without affecting the server or other scans. Unhandled promise rejections and exceptions are logged, not fatal. Graceful shutdown on SIGTERM/SIGINT for containerized redeploys.

**Graceful degradation.** Every optional integration — AI, email, payments, headless rendering — degrades to a working local default instead of blocking the product. There is no "half-configured" broken state.

**Operability.** Single Docker image, SQLite on a persistent volume, a health-check endpoint, and CI that runs typecheck, tests, and build on every push.

---

## 07 — System Architecture

A single Express process serves the API and, in production, the built client — no external queue or worker fleet; a scan job runs in-process and is tracked by status (`queued → scanning → analyzing → complete`). Data lives in one SQLite file (WAL mode), with schema changes applied as additive column migrations rather than destructive rewrites.

| Layer | Choice | Notes |
|---|---|---|
| Frontend | React 19 + Vite 6 + Tailwind 4 | Client-side view state, no URL routing. |
| Backend | Express 4, TypeScript via tsx | Single process; in-process background worker. |
| Data | SQLite (better-sqlite3, WAL) | One file, persistent volume in production. |
| AI | DeepSeek v4-pro / v4-flash | Optional — local fallback when unconfigured. |
| Email | Resend | Optional — console fallback in dev. |
| Payments | Stripe Checkout + webhooks | Optional — purchase flow disabled, not mocked, when unset. |
| Rendering | Playwright (opt-in) | Headless crawl augmentation for SPA/JS-heavy targets. |

---

## 08 — Success Metrics

No targets are committed yet — these are the metrics the product is actually instrumented to answer, proposed as the starting set to track.

**Trust.** Suppression rate per scan (a proxy for false-positive rate) and the share of findings never touched after an "AI reasoning" or evidence view is opened.

**Actionability.** "Fix with AI" prompt copy rate per finding, and repeat-scan score improvement on domains with more than one scan.

**Growth.** Credits purchased per active account, verified-domain share of scanned targets, and MCP-endpoint share of total scans.

---

## 09 — Risks & Open Questions

> **Abuse surface.** The ownership gate stops anonymous attacks against unverified domains, but a malicious actor can still verify a domain they've compromised, or one they're authorized to test but shouldn't be aiming active exploit traffic at from a shared platform. The gate reduces risk; it doesn't eliminate the product's dual-use nature.

> **Single-node ceiling.** The rate limiter is in-memory, the job scheduler is a `setInterval` tick, and the database is one SQLite file — all explicitly acceptable for a single-instance deployment and explicitly not for a horizontally scaled one. This is a known, accepted tradeoff today, not an oversight, but it's a real wall.

> **Model variance.** Thinking-mode reasoning cost and latency vary per scan, and a fast/cheap narration model can occasionally misstate a number in prose even when handed the exact fact — worth continued verification rather than blind trust in model output for anything numeric.

> **Release process.** The working tree currently has no version control history, so "how a change ships" is an open question rather than a documented process.

---

## 10 — Out of Scope / Future Considerations

| Idea | Why it's parked |
|---|---|
| Team / org accounts | Single-user model is simpler and matches today's audience of solo and small-team users. |
| Horizontal scaling (Redis rate limiting, external queue, Postgres) | Not needed until single-node throughput is actually the bottleneck. |
| Compliance report templates | OWASP mapping covers today's audience; SOC2/PCI is a different buyer. |
| Authenticated multi-step crawling | Single supplied auth header covers most API/token-based auth; login-flow automation is a much larger surface. |
| Native mobile app | The audience for this product works from a laptop. |

---

*Seclayer PRD · v1.0 · Reflects the shipped implementation as of this document's writing.*
