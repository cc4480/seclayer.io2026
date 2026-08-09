# Tier 4 — Bilingual Regional Commerce Test Fixture

Real Express + better-sqlite3 app (same fast-build convention as Tiers 1–2 —
no Docker/Supabase needed here; the PRD's Next.js/Postgres/Supabase stack
description is flavor text, the actual planted vulnerabilities are all
generic Express/business-logic bugs), with 7 genuinely vulnerable endpoints
and 3 negative controls (see `vulnerabilities.json`), adapted from
`~/Downloads/vulnapps/TIER4_BILINGUAL_REGIONAL_PRD.md`. Same methodology as
Tiers 1–3: real code, manually verified, scanned live, every gap
investigated to its actual root cause. **Local use only — never expose this
to the internet.**

## Run it

```bash
cd test-targets/tier4-bilingual-regional
npm install
```

Create `.env` in this directory (never committed — see `.gitignore`):

```
PORT=4104
LAREDO_BANK_API_KEY=<any fake value>
LAREDO_BANK_API_SECRET=<any fake value>
STRIPE_WEBHOOK_SECRET=<any fake value>
```

```bash
npm start   # listens on 127.0.0.1:4104
```

## Scan it with Seclayer

1. Add this app's port to `SCAN_DEV_ALLOW_HOSTS` in the main repo's
   `.env.local`: `127.0.0.1:4104`.
2. `npm run dev` in the repo root.
3. `POST /api/login` with `{"email":"admin@laredo-merchant.local","password":"AdminPass!2026"}`
   for a real admin session token to use as `authHeader`.

## Expected / actual results

`vulnerabilities.json`'s `actualResult`/`notes` fields on each entry are the
real, observed outcome — not a prediction. Final tally, after investigating
every gap ("find out why, then fix it" — same discipline as Tiers 1–3):
**4/7 detected with real evidence (2 via new detection capabilities, 2
already working with no fix needed), 3/7 confirmed as deliberate, documented
non-destructive-scanning boundaries.**

| ID | Result | Notes |
|---|---|---|
| T4-i18n-Bypass-001 (locale-route auth bypass) | ✅ **Detected** (new capability) | New `server/i18nProbe.ts` — compares an anonymous caller's auth outcome across locale-swapped sibling paths (`/en/...` vs `/es/...`), symmetric in either direction. Modeled on the existing JWT/BOLA differential pattern. |
| T4-SQLi-Regional-001 (`estado` param) | ✅ **Detected** | Worked first try — the fuzzer's 3rd breaker (`')`) already matches the Postgres/SQLite "near "X": syntax error" pattern fixed in Tiers 1/3, even though its 1st breaker's distinct "unrecognized token" SQLite error format is still unmatched (didn't matter here; noted for the record). |
| T4-Hardcoded-Creds-001 (`.env` leak) | ✅ **Detected** | Same pre-existing sensitive-path capability that caught Tier 3's JWT-secret leak. |
| T4-Token-Reuse-001 (cross-locale reset token) | ⛔ **Not detected — by design** | Proving it means actually changing a real password (locks out the legitimate owner) — AND is fundamentally unobservable to a real scanner anyway (the token is delivered by email in the real world; this fixture only echoes it for local testability). Not built. |
| T4-Price-Manip-001 (USD/MXN price) | ✅ **Detected** (new capability) | Closed by the same `server/priceManipulationProbe.ts` built for T2-BizLogic-001 (same class). Two checkout requests differing only in unit price; fires when the charge total tracks the client price (keyed on computed price×qty, so echoes can't false-fire). Non-destructive — no payment instrument or confirmation is sent, so no charge can complete. |
| T4-SMS-2FA-001 (missing rate limit) | ⛔ **Not detected — by design** | The naive "fire N guesses, check none are throttled" technique risks tripping a REAL target's lockout policy and locking out its legitimate user — a real, uninvited disruption. Not built. |
| T4-Stripe-Webhook-001 (currency-conditional signature check) | ⛔ **Not detected — by design** | Proving it means the target's real webhook handler processes a fake "payment succeeded" event — real order/credit/email side effects on a live target. Not built. |

**Why four vulnerabilities were deliberately left undetected.** All four
share the same root property as Tier 2's price-manipulation/prototype-
pollution/race-condition gaps: every active probe already in this codebase
(BOLA, NoSQLi, XXE, JWT, weak-token, the new i18n differential) proves itself
via a read, an out-of-band callback, or a response differential — never by
completing a real mutating action or risking a real defensive side effect
(account lockout) against a live target. These four can only be proven by
crossing that line, so they were investigated, confirmed genuinely
undetected, and intentionally not built — a permanent, principled boundary
for black-box scanning, not a gap to revisit. See `notes` on each entry in
`vulnerabilities.json` for the full reasoning.

## All four tiers — final tally

| Tier | Detected | Documented non-destructive/architectural boundary | New/fixed capabilities this session |
|---|---|---|---|
| 1 (OWASP Foundation) | 7/7 | 0 | 5 |
| 2 (Advanced Attack Chains) | 5/8 | 3/8 | 2 |
| 3 (Supabase BaaS) | 4/9 (+1 predicted, +1 partial) | 2/9 architectural + 1/9 non-reproducible | 3 |
| 4 (Bilingual/Regional) | 4/7 | 3/7 | 1 |
