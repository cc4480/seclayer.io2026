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
     ]
   }
   ```

## Actual results (verified 2026-08-08, scan_a0a43100290b83c6)

`vulnerabilities.json`'s `actualResult` field on each entry is the real,
observed outcome — not a prediction. Final tally: **4/7 detected with real
evidence, 3/7 confirmed gaps.**

| ID | Result | Notes |
|---|---|---|
| T1-SQLi-001 | ✅ **Detected** (after a fix) | `SQL_ERROR_SIGNATURE` had no pattern for better-sqlite3's real error text — fixed in `server/redTeam/sqlInjection.ts` + `server/paramFuzzer.ts` |
| T1-XSS-Reflected-001 | ✅ **Detected** | Worked first try |
| T1-XSS-Stored-001 | ✅ **Detected** (after a fix) | The probe never checked the page a form was actually found on (only its action URL + site root) — added `InjectableTarget.discoveredOnPage` in `server/crawler.ts`, used it in `server/storedXss.ts`. Also fixed a bug in this fixture itself (missing hidden `postId` field broke the crawler's raw form POST). |
| T1-IDOR-001 | ✅ **Detected** | Worked first try, with `bolaIdentities` supplied |
| T1-Auth-001 (weak token) | ❌ **Gap** | No token-entropy/prediction probe exists |
| T1-AccessControl-001 | ❌ **Gap** | The "Exposed User Object" probe only checks the fixed path `/api/v1/users/admin`, not arbitrary admin endpoints |
| T1-DataExposure-001 | ❌ **Gap** | SAST secret-signature scanning only runs on the root page's HTML, never crawled sub-pages or JSON responses |

Two real product bugs were found and fixed by this exercise — not just gaps
documented, but detection Seclayer already claims to do and genuinely wasn't:
SQLi against any Node+SQLite target (the stack Seclayer's own backend uses),
and stored XSS on any app where the form and its display page differ (a very
common REST pattern). Both fixes are covered by new regression tests
(`server/redTeamProbes.test.ts` path indirectly, `server/storedXss.test.ts`,
`server/crawler.test.ts`).

The remaining 3 gaps are real and documented, not something to route around —
see `vulnapps-benchmark` in project memory for why this is expected and how
it should be used (roadmap input, not a fixture bug).
