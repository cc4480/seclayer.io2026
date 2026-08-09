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
**6/7 detected (5 at high confidence with real PROVEN evidence, 1 —
SMS-2FA — at MEDIUM confidence / needs-verification, since absence of a rate
limit can't be positively proven); 1/7 (cross-locale token reuse) a genuine
non-destructive boundary.**

| ID | Result | Notes |
|---|---|---|
| T4-i18n-Bypass-001 (locale-route auth bypass) | ✅ **Detected** (new capability) | New `server/i18nProbe.ts` — compares an anonymous caller's auth outcome across locale-swapped sibling paths (`/en/...` vs `/es/...`), symmetric in either direction. Modeled on the existing JWT/BOLA differential pattern. |
| T4-SQLi-Regional-001 (`estado` param) | ✅ **Detected** | Worked first try — the fuzzer's 3rd breaker (`')`) already matches the Postgres/SQLite "near "X": syntax error" pattern fixed in Tiers 1/3, even though its 1st breaker's distinct "unrecognized token" SQLite error format is still unmatched (didn't matter here; noted for the record). |
| T4-Hardcoded-Creds-001 (`.env` leak) | ✅ **Detected** | Same pre-existing sensitive-path capability that caught Tier 3's JWT-secret leak. |
| T4-Token-Reuse-001 (cross-locale reset token) | ⛔ **Not detected — by design** | Proving it means actually changing a real password (locks out the legitimate owner) — AND is fundamentally unobservable to a real scanner anyway (the token is delivered by email in the real world; this fixture only echoes it for local testability). Not built. |
| T4-Price-Manip-001 (USD/MXN price) | ✅ **Detected** (new capability) | Closed by the same `server/priceManipulationProbe.ts` built for T2-BizLogic-001 (same class). Two checkout requests differing only in unit price; fires when the charge total tracks the client price (keyed on computed price×qty, so echoes can't false-fire). Non-destructive — no payment instrument or confirmation is sent, so no charge can complete. |
| T4-SMS-2FA-001 (missing rate limit) | 🟡 **Detected — MEDIUM confidence** (new capability) | New `server/authRateLimitProbe.ts` — a small bounded burst (6 wrong codes) that bails the instant any throttle signal appears (429, `RateLimit-*`/`Retry-After`, or a lockout message). The one finding intentionally NOT at high confidence / not PROVEN: absence of a control can't be positively proven from a bounded sample. Fires on `/api/auth/verify-sms`; correctly stays quiet on the rate-limited `-safe` sibling. |
| T4-Stripe-Webhook-001 (currency-conditional signature check) | ✅ **Detected** (new capability) | New `server/webhookSignatureProbe.ts` — the signature skip is gated on *currency*, not event type, so the probe sends a zero-amount `charge.failed` (a FAILURE event) for a *nonexistent* entity: accepting it processes nothing of value. Proof is the differential — same invalid signature rejected for USD, accepted for MXN. This is the less-invasive route that replaced the earlier "would process a forged payment" objection. |

**Why the one remaining vulnerability is genuinely undetectable.** Three of
the four originally-undetected vulns here were re-examined and closed once a
safe oracle was found: price tampering (reads a quote, no payment sent),
webhook bypass (a zero-amount failure event for a nonexistent entity — nothing
of value is processed), and SMS-2FA (a small bounded burst at honest medium
confidence). The one true holdout is **cross-locale reset-token reuse**: it is
double-blocked. The reset token is email-delivered, so a black-box scanner
never sees it (this fixture only echoes it for local testability); and
redeeming it changes the victim's password — a destructive, account-altering
write. It cannot be proven non-destructively, and it isn't reachable even with
a destructive mode unless the scanner is handed a real emailed token. See
`notes` in `vulnerabilities.json`.

## All four tiers — final tally

| Tier | Detected | Documented non-destructive boundary | Not a vulnerability |
|---|---|---|---|
| 1 (OWASP Foundation) | 7/7 | 0 | 0 |
| 2 (Advanced Attack Chains) | 7/8 | 1/8 (race condition) | 0 |
| 3 (Supabase BaaS) | 8/9 | 0 | 1/9 (Realtime-hijack, hardened) |
| 4 (Bilingual/Regional) | 6/7 (1 at medium confidence) | 1/7 (token reuse) | 0 |
| **Total** | **28/31** | **2** (race condition, token reuse) | **1** (not a real vuln) |
