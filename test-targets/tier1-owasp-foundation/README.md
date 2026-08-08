# Tier 1 — OWASP Foundation Test Fixture

Real, working Express + SQLite app with 7 genuinely vulnerable endpoints and 3
negative controls (see `vulnerabilities.json`), adapted from
`~/Downloads/vulnapps/TIER1_OWASP_FOUNDATION_PRD.md`. Built to verify what
Seclayer's actual scanner detects — not simulated responses like
`test-targets/vulnerable-app.mjs`, real SQL/rendering/session logic against an
in-memory SQLite DB seeded with fake data. **Local use only — never expose
this to the internet.**

## Run it

```bash
cd test-targets/tier1-owasp-foundation
npm install
npm start                    # listens on 127.0.0.1:4101
```

## Scan it with Seclayer

1. In the main repo's `.env.local`, add this app's port to
   `SCAN_DEV_ALLOW_HOSTS` (comma-separated), e.g.:
   ```
   SCAN_DEV_ALLOW_HOSTS="127.0.0.1:4100,127.0.0.1:4101"
   ```
   `DEV_SKIP_DOMAIN_VERIFICATION="true"` (already set) unlocks active probes.
2. `npm run dev` in the repo root.
3. Launch a scan at `http://127.0.0.1:4101` from the dashboard, or via
   `test-targets/scan-apps.mjs` with an `apps.json` entry — for T1-IDOR-001,
   supply `bolaIdentities` after logging in as both seeded users:
   ```bash
   curl -s -X POST http://127.0.0.1:4101/login -H 'Content-Type: application/json' \
     -d '{"username":"carlos","password":"CarlosPass!2026"}'   # → token for invoice 1
   curl -s -X POST http://127.0.0.1:4101/login -H 'Content-Type: application/json' \
     -d '{"username":"test","password":"TestPass!2026"}'       # → token for invoice 2
   ```
   ```json
   {
     "url": "http://127.0.0.1:4101",
     "expect": ["SQL Injection", "Reflected XSS", "Stored XSS", "Broken Object Level Authorization"],
     "bola": [
       { "label": "carlos", "authHeader": "Bearer <carlos-token>", "ownResource": "/api/invoice/1", "ownMarker": "Carlos Consulting LLC" },
       { "label": "test",   "authHeader": "Bearer <test-token>",   "ownResource": "/api/invoice/2", "ownMarker": "Competitor Corp" }
     ],
     "loginCredentials": { "username": "carlos", "password": "CarlosPass!2026" }
   }
   ```
   `loginCredentials` (real, valid credentials for a target you own — never
   guessed) unlocks the weak-session-token probe: it logs in once and tries
   to reproduce the resulting token from common weak recipes.

## Actual results (verified 2026-08-08, scan_a9c23e6ed997bd27)

`vulnerabilities.json`'s `actualResult`/`notes` fields on each entry are the
real, observed outcome — not a prediction. Final tally, after three rounds of
"find out why, then fix it": **7/7 detected with real evidence.**

| ID | Result | Notes |
|---|---|---|
| T1-SQLi-001 | ✅ **Detected** (after a fix) | `SQL_ERROR_SIGNATURE` had no pattern for better-sqlite3's real error text — fixed in `server/redTeam/sqlInjection.ts` + `server/paramFuzzer.ts` |
| T1-XSS-Reflected-001 | ✅ **Detected** | Worked first try |
| T1-XSS-Stored-001 | ✅ **Detected** (after a fix) | The probe never checked the page a form was actually found on — added `InjectableTarget.discoveredOnPage` (`server/crawler.ts`), used in `server/storedXss.ts` |
| T1-IDOR-001 | ✅ **Detected** | Worked first try, with `bolaIdentities` supplied |
| T1-AccessControl-001 | ✅ **Detected** (after a fix) | The "Exposed User Object" probe only checked one fixed path and one object shape — broadened to a small candidate-path list, made array-aware (`server/apiProbes.ts`) |
| T1-DataExposure-001 | ✅ **Detected** (after a fix) | SAST secret-signature scanning only ever ran on the root page — the crawler now captures every fetched response body/headers regardless of content type (`CrawlCapture` in `server/crawler.ts`), and `server/scanner.ts` runs secret + cookie-flag analysis against all of them |
| T1-Auth-001 (weak token) | ✅ **Detected** (new capability) | New `server/redTeam/weakSessionToken.ts` probe — see below, it's not generic entropy analysis |

**How T1-Auth-001 was actually closed.** Generic statistical "randomness
testing" of the token was considered and rejected: MD5's output is uniformly
distributed no matter how weak its input is, so a hash of a predictable seed
is statistically indistinguishable from a real CSPRNG output — that
technique would give a false sense of coverage on exactly this pattern.
Instead, with real credentials the *caller* explicitly supplies (never
guessed — same trust model as `authHeader`/`bolaIdentities`, so this does
NOT reopen `prd.md`'s "no autonomous login-form crawling" non-goal), the
scanner logs in exactly once, captures the token, then tries to reproduce it
**offline** from a small set of common `(seed, algorithm)` recipes across a
short timestamp window around the real request. An exact byte-for-byte match
is definitive proof, not a probabilistic guess — the odds of a spurious
collision across a few dozen candidates against a 128+ bit hash are
negligible. New scan option `loginCredentials`, threaded through
`routes/scans.ts` → `scanWorker.ts` → `scanner.ts`.

Along the way this also fixed a real crash in this fixture's own `auth.js`:
once `/login` became a legitimately fuzzed discovered-form target,
better-sqlite3 threw (rather than just not matching) when a fuzz payload
handed it a non-string bound parameter. And the new probe was deliberately
ordered to run *before* discovered-parameter fuzzing, since fuzzing hits the
same login endpoint with many payloads and can exhaust its rate limiter
before the probe's one legitimate login gets a turn.

Five real product bugs were found and fixed by this exercise, plus one new
detection capability added — not just gaps documented, but detection
Seclayer already claims to do and genuinely wasn't: SQLi against any
Node+SQLite target (the stack Seclayer's own backend uses), stored XSS on
any app where the form and its display page differ (a common REST pattern),
broken access control on any admin/user-list path other than one hardcoded
guess, secrets exposed on any non-root page or JSON API response, and now
predictable session tokens via a real, caller-authorized login. All are
covered by new regression tests (`server/storedXss.test.ts`,
`server/crawler.test.ts`, `server/passiveScan.test.ts`, `server/scanner.test.ts`,
`server/staticAnalysis.test.ts`, `server/redTeam/weakSessionToken.test.ts`).
