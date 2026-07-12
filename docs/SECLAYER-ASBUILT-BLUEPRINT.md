# Seclayer — As-Built Master Blueprint

> Closed-source, pay-per-scan black-box penetration-testing SaaS + MCP server for vibe coders and developers.
> Documents what is **actually built** as of July 2026, reconstructed from live product output + the Seclayer PRD v1.0 + development history.
> **`[VERIFY]`** = inferred from screenshots, Claude Code must confirm against repo. **`[BUG]`** = known defect observed in live output, needs fixing.
>
> **Reconciled against repo commit `8539ad1` (2026-07-11).** `[VERIFIED ✓]` markers below were confirmed against the code; the biggest change since reconstruction: the active-exploitation modules (RED_TEAM / API_SEC) **now fire and are covered by 138 passing evidence-backed tests** — see §4 and §2a.

---

## 0. How to use this document

As-built map of the real product, not a spec of intent. Seclayer shares its scanning/scoring engine with VibeScan but adds **active exploitation** (behind an ownership gate) and the **monetization + MCP** layers. It stays **closed source** specifically because the active-exploitation modules are dangerous in open hands.

**Core promise:** every finding is directly actionable — by the human reading it and by the AI coding agent they hand it to. Signature-confirmed findings, plain-English impact, stack-tailored fix, ready-to-paste agent prompt.

---

## 1. Product identity

| Attribute | Value |
|---|---|
| Name | Seclayer (`[ sec ]layer`) |
| Type | Pay-per-scan black-box pen-testing SaaS + MCP server |
| Domain | seclayer.io |
| Audience | Solo devs, agent-native engineers, automation/CI users, small SaaS operators |
| License | **Closed source** (deliberate — active exploitation) |
| Repo | github.com/cc4480/seclayer.io2026 `[VERIFIED ✓]` (memory/spec tracked separately in private `cc4480/seclayer-claude-memory`) |
| Tagline | "Security layer for every deploy" |
| Relationship to VibeScan | Shares engine; Seclayer = active/closed/monetized, VibeScan = passive/open |

---

## 2. The seven-pillar architecture (as-built, observed live)

Report is organized into seven AppSec pillars, each with live counts and a risk label:

| Pillar | Full name | What it covers | Active/Passive |
|---|---|---|---|
| **SAST** | Static Analysis | Exposed-secret signatures in served HTML/JS (Stripe, GitHub, AWS, Google keys, PEM blocks), confidence-rated | Passive |
| **DAST** | Dynamic Audit | Sensitive-path probing (`.env`, `.git/config`, `.git/HEAD`, `phpinfo.php`, `.aws/credentials`, `config.json`), crawler mapping links/forms/JS endpoints, param fuzzing | Passive recon + **active fuzz (gated)** |
| **IAST** | Interactive Policies | Security header presence + cookie flags | Passive |
| **SCA** | Composition Review | Known-vulnerable JS library versions → CVEs | Passive |
| **EASM** | Attack Surface | DNS resolution, authoritative NS, subdomain enumeration (33 common names, wildcard-aware), server/framework signature leaks | Passive |
| **API_SEC** | API Security Testing | GraphQL introspection exposure, BOLA/IDOR probe on enumerated-resource pattern | **Active (gated)** |
| **RED_TEAM** | Red Team Active Probes | Active SQLi, reflected-XSS, OS command injection, SSRF — root URL + discovered params | **Active (gated)** |

Plus a **Templates** data-driven detection pack `[VERIFIED ✓]` (`server/templates.ts` + `templateEngine.ts`, tested) — exposed admin panels, actuators, config/backup files, `.htpasswd`, subdomain-takeover fingerprints, WP user enumeration, `.netrc` — gated by detected tech stack, extensible without code changes.

---

## 2a. Evidence tiers — PROVEN / DETECTED `[VERIFIED ✓]` (new since reconstruction)

The trust-gate work not present in the original reconstruction. Every active finding now carries a replayable **`ExploitEvidence`** receipt (request + response + quoted signal + demonstration + curl):

- **PROVEN** — `isProven` requires `signal.quote` to be a **literal substring** of the captured attack response, so the product can never claim a byte it didn't capture. All eight active probes emit PROVEN receipts end-to-end against a deliberately vulnerable test target (`test-targets/vulnerable-app.mjs`).
- **DETECTED** — a real signal seen but not demonstrated end-to-end; shown with what was observed. Not a demotion — the honest badge.
- **Blind SSRF (out-of-band):** the app is its own OAST collaborator (`server/oob.ts`). It mints a unique 48-hex CSPRNG token URL, injects it, and a **recorded callback from the target IS the proof** — proving blind SSRF that reflects nothing inline. Token guarded to a 15-minute replay window; endpoint can't be used as an open write store.
- **BOLA/IDOR:** upgraded to a **two-identity differential** — baseline (A reads own) + attack (A reads B's object → gets B's marker) + negative control (unauth → 401). A single-request "enumerated resource" is no longer labelled BOLA.

---

## 3. Observed report structure (live)

### 3.1 Executive header
- **AppSec Score /100 + Grade + Posture Rating** (observed 31/F/MODERATE on google.com, 100/INFO on securityscanner.dev)
- **Score Delta / Findings Delta** boxes (vs previous scan) `[VERIFY populate logic]`
- **"DEEPSEEK AI ANALYST VERIFIED"** badge
- Seven pillar tabs with counts + a raw-console tab (`>_`)

### 3.2 Executive Overview tab
- **Executive Summary** — DeepSeek-written, plain English
- **"How the AI assessed this (chain-of-thought)"** — expandable reasoning trace (observed reasoning about not overstating header-absence confidence — good discipline)
- **Detailed Executive Breakdown** — Key Risk Areas (2-col cards), Business Impact, **Priority Actions (ranked)**
- Pillar summary cards (SAST/DAST/IAST/SCA/EASM/API_SEC/RED_TEAM) with risk labels

### 3.3 Per-finding detail
- Severity badge + **OWASP mapping** (e.g. A05:2021) + **Confidence tag** (e.g. `CONF: MEDIUM`) + finding ID (e.g. `f_gen_4_25c8`)
- Description + **Impact** line
- **Automated Remediation Fix** (copy directive)
- **"Fix with AI — paste into Cursor / Claude Code / Windsurf"** — numbered agent-ready prompt (copy prompt)
- **"Mark false positive"** button

### 3.4 Reconnaissance / diagnostics
- **Network & Attack Surface (EASM):** resolved IP, nameserver, protocol/status, server header, live subdomains
- **Dynamic Coverage (DAST):** sensitive paths probed (X locked down), crawl coverage (pages/endpoints), params fuzzed (or "skipped (unverified)"), detected libraries
- **Diagnostic Raw Headers & Outputs** — real captured scan trace (GET request, resolved IP, subdomains probed, per-path 404/403 results)
- **Playwright screenshot of the target URL** `[VERIFY — recently added]`

---

## 4. Ownership verification gate (as-built, critical)

Active exploitation (RED_TEAM, API_SEC, param fuzzing) is **gated** behind proof of domain ownership. Passive recon always runs.

- **DNS TXT** at `_seclayer-challenge.<domain>` with server-issued token, **OR**
- **Well-known file** at `/.well-known/seclayer-verification.txt`
- Both implemented in `server/domainVerify.ts`. Gating is `allowActiveProbes = requestedActive && db.isDomainVerified(...)` (`server.ts:274, 575, 715`), so an owner can also opt into passive-only on a verified domain.
- Unverified scans include an explicit **INFO finding** disclosing active probing was skipped and why — the gate is **never silent**. `[VERIFIED ✓]` (test-locked in `scanner.test.ts`; a companion test proves passive mode sends **zero** exploit payloads against a would-be-vulnerable target).

**SSRF protection** `[VERIFIED ✓]` — *stronger than described*: `isBlockedIp` blocks loopback, RFC1918, link-local, cloud-metadata, CGNAT, and IPv6 equivalents; internal hostnames rejected. Beyond redirect-hop re-validation, a **DNS-rebinding TOCTOU fix** pins every user-target request to an undici `safeDispatcher` that validates IPs *at connect time* (`firstBlockedAddress`, `guardedFetch`), so a low-TTL rebinding resolver can't answer public to the check and internal to the socket. Applied to scan targets, webhooks (`notify.ts`), and ownership checks (`domainVerify.ts`) alike.

> **STATUS `[VERIFIED ✓ — 8539ad1]`:** The active modules **fire and are proven working.** All eight (SQLi, reflected XSS, OS command-injection, reflected + **blind out-of-band** SSRF, GraphQL introspection, two-identity BOLA, discovered-parameter fuzzer) produce PROVEN evidence receipts end-to-end against `test-targets/vulnerable-app.mjs`, covered by 138 passing tests. This was the blueprint's #1 open unknown — **now closed.**

---

## 5. AI layer — DeepSeek (as-built)

- **deepseek-v4-pro** — deep report: rewrites findings (attacker's-eye + stack fix + impact + agent prompt), executive summary, structured breakdown. Thinking mode. `[VERIFIED ✓]` — `MODEL_PRO = process.env.DEEPSEEK_MODEL_PRO || 'deepseek-v4-pro'` (explicit ID, `deepseek.ts:12`).
- **deepseek-v4-flash** — live narration during scan, low-latency `[VERIFIED ✓]` (`narrate.ts` / `deepseekClient.ts`).
- **Deterministic local fallback** for every AI field — product functional with no AI key `[VERIFIED ✓]` (tested in `deepseek.test.ts` with no key set).

### `[BUG]` AI invents its own score — **MITIGATED AT DISPLAY `[VERIFIED ✓]`, residual guard open**
Original: score box `31/F` but AI prose says "85/100" — contradictory. **Current state:** the model is still *asked* for `adjustedScore` and the raw AI figure is stored (`deepseek.ts:155`, `server.ts:660`), **but every read path recalculates the score deterministically** from finding severities (`recalculateScore` via `getScanWithSuppressedFindings`), and scan-completion narration deliberately narrates the deterministic figure precisely so it can't contradict the report the user opens (`server.ts:639–644`). **The visible box/prose contradiction is therefore resolved — the displayed score is deterministic.**
**Residual (still worth the §5 fix):** the model is not yet forbidden from stating a number inside `aiSummary` prose, and the stored `score` field still holds the AI value (a trap for any consumer reading it raw instead of through the suppression read-model). Close by injecting the deterministic score into the prompt + a post-process prose guard. (See SECLAYER-FIXES.md.)

---

## 6. Known bugs (observed live — fix list)

| ID | Bug | Status |
|---|---|---|
| `[BUG]` 1 | AI summary states a different score than the deterministic box | **Mitigated at display** — score is recalculated deterministically on every read (`server.ts:639–644`); box/prose contradiction gone. Residual: no prose-number guard yet. See §5. |
| `[BUG]` 2 | Score calibration too harsh — google.com scored F for missing-header/cookie findings | **Open — needs live/VibeScan comparison.** Missing-header severity is now clamped ≤ medium in code (`deepseek.ts:183`, `scanner.ts`), which should soften this; verify against a live scan. |
| `[BUG]` 3 | Seclayer scoring drifted from VibeScan's calibrated engine | **Cannot confirm from this repo** (no VibeScan engine here). Scoring is centralized in `server/scoring.ts`; cross-repo consolidation still to verify. |
| `[BUG]` 4 (earlier) | Hard-coded alarmist banner on minor findings | **Appears fixed `[VERIFIED ✓]`** — banner is severity-derived; tests assert no red alarm for info/low worst-case (`scoring.test.ts`). |
| `[BUG]` 5 (earlier) | `$lovable.dev` / template-variable leaking into subdomain display | **Open — needs live scan to reproduce**; not reproducible from static repo review. |
| `[BUG]` 6 (earlier) | "2 high vs 1 confirmed" summary/detail count mismatch | **Open — needs live scan.** Posture counts now derive from one source (`scoring.ts`, tested for agreement), which should prevent it; confirm live. |

---

## 7. Monetization (as-built per PRD)

- **Credits** — 1 credit = 1 scan (dashboard, monitor tick, or MCP). Observed credit balance in UI (e.g. "Credits: 82").
- **Stripe packs** — single / 5-pack / 20-pack; credits granted only by a **signature-verified** webhook (`constructEvent`, `stripe.ts:82`) on `checkout.session.completed`, never on checkout click `[VERIFIED ✓ — signature]`. *(Idempotency of credit-granting: not clearly located — verify a duplicate webhook can't double-grant.)*
- **5 free credits** on signup `[VERIFY]`
- **Continuous Monitoring** — $129/yr per URL: risk-adaptive cadence (A=14d, B/C=7d, D/F=3d), CVE+EPSS alerts, regression detection, cert-expiry alerts `[VERIFY implemented vs planned]`

---

## 8. Developer / MCP surface (as-built per PRD)

- **`POST /api/mcp/scan`** `[VERIFIED ✓]` (`server.ts:553`) — API-key auth (validate + deduct 1 credit), SSRF pre-check on the target before spending, runs the full diagnostic + AI pipeline (incl. the OOB collaborator), returns the same report quality as the dashboard. Active probes gated by the same `isDomainVerified` check.
- API keys shown once at creation, stored hashed + masked preview `[VERIFY]`

---

## 9. System architecture (as-built per PRD)

- Single Express process serves API + built client; in-process job worker (`queued → scanning → analyzing → complete`); no external queue `[VERIFY]`
- **SQLite (WAL)** single file, persistent volume; additive column migrations `[VERIFY]`
- Auth: passwordless magic-link, SHA-256 hashed tokens, httpOnly session cookie `[VERIFY]`
- Single-node ceiling (in-memory rate limiter, setInterval scheduler) — accepted tradeoff per PRD

---

## 10. Top open tasks (as-built reality)

In priority order — updated to the verified state at `8539ad1`:

1. ~~**Verify active-exploitation modules actually fire.**~~ **DONE `[VERIFIED ✓]`** — all eight modules fire with PROVEN evidence receipts against `test-targets/vulnerable-app.mjs`; 138 passing tests. Was the #1 unknown.
2. **Close the residual score-authority gap** — the displayed score is already deterministic (recalculated on read), but add the §5 guard: inject the deterministic score into the prompt and forbid the model from stating its own number in prose; consider storing the deterministic score in the `score` field too. → SECLAYER-FIXES.md
3. **Calibration + count bugs (2, 3, 5, 6) need a live scan / VibeScan comparison** — several have code-level mitigations already (header clamp, single-source posture counts); confirm against real targets and reconcile scoring with VibeScan.
4. **DeepSeek model string confirmed `[VERIFIED ✓]`** — explicit `deepseek-v4-pro` via env, no legacy aliases in code.
5. **Version control confirmed `[VERIFIED ✓]`** — repo at `github.com/cc4480/seclayer.io2026`, pushed to `origin/main`; `.gitignore` excludes `.env*`, `data.sqlite*`, and `.claude/`.

---

## 11. Verified against commit `8539ad1` (2026-07-11)

This section was the reconciliation task; it is now closed. Results:

1. **`[VERIFY]` items walked** — seven pillars (§2) map to real modules in `server/scanner.ts` + the tested Templates pack; ownership gate (§4) and SSRF protection (§4, DNS-rebinding-hardened) confirmed; MCP `POST /api/mcp/scan` (§8) confirmed with credit deduction + SSRF pre-check; DeepSeek model IDs, local fallback, SQLite WAL, magic-link auth (§9) confirmed.
2. **Active modules (§2 RED_TEAM/API_SEC) execute — not placeholders.** All eight produce PROVEN, replayable evidence receipts; 138 passing tests. This was the single most important unknown and is now resolved.
3. **BUG 1 mitigated at display** (deterministic score on read); BUG 4 fixed; BUGS 2/3/5/6 have code-level mitigations but still need a live scan / VibeScan comparison to fully confirm.
4. **Still open:** the §5 prose-score guard (residual), live calibration confirmation, and cross-repo scoring consolidation with VibeScan.

**Not in the original reconstruction, now built:** PROVEN/DETECTED evidence tiers (§2a), out-of-band blind-SSRF collaborator, two-identity BOLA, DNS-rebinding SSRF hardening, and real continuous-monitoring schedule + regression alerting (§7).

---

*Seclayer As-Built Blueprint · reconstructed July 2026 · reconciled against `8539ad1` on 2026-07-11. Companion: SECLAYER-FIXES.md, VIBESCAN-ASBUILT-BLUEPRINT.md.*
