# Tier 2 — Advanced Attack Chains Test Fixture

Real, working Express + JWT app with 8 genuinely vulnerable endpoints and 4
negative controls (see `vulnerabilities.json`), adapted from
`~/Downloads/vulnapps/TIER2_ADVANCED_ATTACK_CHAINS_PRD.md`. Same approach as
`test-targets/tier1-owasp-foundation`: real code, not simulated responses,
built to verify what Seclayer's actual scanner detects. **Local use only —
never expose this to the internet.**

Two deliberate adaptations from the original PRD, both explained in
`vulnerabilities.json`:
- **JWT alg:none** is reproduced via a hand-rolled verifier, not
  `jsonwebtoken`'s own `verify()` — modern `jsonwebtoken` (confirmed against
  v9.0.3) hard-requires a signature once a secret is supplied, closing this
  bug at the library level even if `'none'` is naively allow-listed.
- **Insecure deserialization** is adapted from the PRD's PHP
  `unserialize()`/magic-method example to its real Node.js equivalent:
  **prototype pollution** via an unguarded recursive merge — PHP's specific
  mechanism has no direct Node analog, but this is a real, common, CVE-worthy
  vulnerability class with comparable impact.

## Run it

```bash
cd test-targets/tier2-advanced-attack-chains
npm install
npm start                    # listens on 127.0.0.1:4102
```

## Scan it with Seclayer

1. Add this app's port to `SCAN_DEV_ALLOW_HOSTS` in the main repo's
   `.env.local`:
   ```
   SCAN_DEV_ALLOW_HOSTS="127.0.0.1:4100,127.0.0.1:4101,127.0.0.1:4102"
   ```
2. `npm run dev` in the repo root.
3. Log in as both seeded users to get real JWTs for the two-identity BOLA
   check (T2-HorzPrivEsc-001), then launch a scan supplying `authHeader`,
   `bolaIdentities`, `activeProbes: true`, and `aggressiveProbes: true`:
   ```bash
   curl -s -X POST http://127.0.0.1:4102/api/login -H 'Content-Type: application/json' \
     -d '{"username":"alice","password":"AlicePass!2026"}'   # → token for document 1001
   curl -s -X POST http://127.0.0.1:4102/api/login -H 'Content-Type: application/json' \
     -d '{"username":"bob","password":"BobPass!2026"}'       # → token for document 1002
   ```
   ```json
   {
     "url": "http://127.0.0.1:4102",
     "activeProbes": true,
     "aggressiveProbes": true,
     "authHeader": "Bearer <alice-token>",
     "bolaIdentities": [
       { "label": "alice", "authHeader": "Bearer <alice-token>", "ownResource": "/api/document/1001/share", "ownMarker": "Alice Project Plan" },
       { "label": "bob",   "authHeader": "Bearer <bob-token>",   "ownResource": "/api/document/1002/share", "ownMarker": "Bob Project Plan" }
     ]
   }
   ```

## Expected / actual results

`vulnerabilities.json`'s `actualResult`/`notes` fields on each entry are the
real, observed outcome — not a prediction. Final tally, after investigating
every gap ("find out why, then fix it" — same discipline as Tier 1): **5/8
detected with real evidence; 3/8 confirmed as deliberate, documented scope
boundaries, not bugs.**

| ID | Result | Notes |
|---|---|---|
| T2-PrivEsc-001 (JWT alg:none → role:admin) | ✅ **Detected** (after two fixes) | The probe only tested the scan's root URL — broadened to a candidate-path list. Still missed after that: the forged token reused the caller's own non-admin claims, so a route that ALSO checks `role` correctly 403'd it — added a second forgery variant that escalates role/isAdmin/admin claims (`server/jwtProbe.ts`) |
| T2-NoSQLi-001 | ✅ **Detected** | Worked first try |
| T2-XXE-001 | ✅ **Detected** | Worked first try |
| T2-HorzPrivEsc-001 (BOLA) | ✅ **Detected** | Worked first try, with `bolaIdentities` supplied |
| T2-WeakCrypto-001 (weak reset token) | ✅ **Detected** (new capability) | New `server/weakTokenScan.ts` — scans JSON responses the param-fuzzer captures for short/low-entropy security-token fields. Wired into `server/paramFuzzer.ts` + `server/scanner.ts` |
| T2-BizLogic-001 (price manipulation) | ⛔ **Not detected — by design** | Proving it requires completing a real checkout (order/inventory/webhook side effects) against an arbitrary target — violates the product's non-destructive guarantee. Not built. |
| T2-Deser-001 (prototype pollution) | ⛔ **Not detected — by design** | Proving it requires polluting `Object.prototype` process-wide on the target, which can corrupt/crash unrelated request handling for as long as it stays up — same non-destructive boundary. Not built. |
| T2-RaceCondition-001 | ⛔ **Not detected — by design** | Proving it requires actually causing a double-spend via concurrent requests against a real financial endpoint — same non-destructive boundary. Not built. |

**Why three vulnerabilities were deliberately left undetected.** Every active
probe already in this codebase (BOLA, NoSQLi, XXE, JWT, weak-token) proves
itself through a *read*, an out-of-band callback, or a response differential —
never by actually completing a state-mutating write with real consequences.
The three gaps above (price manipulation, prototype pollution, race
condition) can only be proven by actually causing the harmful outcome — a
real order, real global process corruption, a real double-spend — on
whatever target Seclayer is pointed at, which could be someone else's
production system. That's a different risk category from every other probe
in this product, so these were investigated, confirmed genuinely undetected,
and intentionally not built, rather than fixed. See `notes` on each entry in
`vulnerabilities.json` for the full reasoning.
