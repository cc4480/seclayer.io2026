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
every gap ("find out why, then fix it" — same discipline as Tier 1): **7/8
detected with real evidence; 1/8 (the race condition) a deliberate,
documented scope boundary, not a bug.**

| ID | Result | Notes |
|---|---|---|
| T2-PrivEsc-001 (JWT alg:none → role:admin) | ✅ **Detected** (after two fixes) | The probe only tested the scan's root URL — broadened to a candidate-path list. Still missed after that: the forged token reused the caller's own non-admin claims, so a route that ALSO checks `role` correctly 403'd it — added a second forgery variant that escalates role/isAdmin/admin claims (`server/jwtProbe.ts`) |
| T2-NoSQLi-001 | ✅ **Detected** | Worked first try |
| T2-XXE-001 | ✅ **Detected** | Worked first try |
| T2-HorzPrivEsc-001 (BOLA) | ✅ **Detected** | Worked first try, with `bolaIdentities` supplied |
| T2-WeakCrypto-001 (weak reset token) | ✅ **Detected** (new capability) | New `server/weakTokenScan.ts` — scans JSON responses the param-fuzzer captures for short/low-entropy security-token fields. Wired into `server/paramFuzzer.ts` + `server/scanner.ts` |
| T2-BizLogic-001 (price manipulation) | ✅ **Detected** (new capability) | New `server/priceManipulationProbe.ts` — two checkout requests differing only in unit price; if the charge total tracks the client price (keyed on the computed price×qty, so a plain echo can't false-fire) the server trusts client pricing. Non-destructive: sends no payment instrument and no confirmation, so it elicits at most a quote, never a real charge. Aggressive+owned. |
| T2-Deser-001 (prototype pollution) | ✅ **Detected** (new capability) | New `server/prototypePollutionProbe.ts` — proves it non-destructively via the benign `json spaces` formatting gadget (a request flips the app's JSON output compact→indented), gated to the aggressive+ownership tier, with a best-effort revert. The "trigger a real side effect" concern is real but here the effect is purely cosmetic whitespace and self-heals on restart — an acceptable trade unlike the two below. Note: modern Express (4.21.2) patched its *own* json-spaces read, so the observable is the app's own unguarded config read (see `vulnerabilities.json`). |
| T2-RaceCondition-001 | ⛔ **Not detected — by design** | Proving it requires actually causing a double-spend via concurrent requests against a real financial endpoint — same non-destructive boundary. Not built. |

**Why the one remaining vulnerability is deliberately left undetected.**
Every active probe in this codebase (BOLA, NoSQLi, XXE, JWT, weak-token,
prototype pollution, and now price tampering) proves itself through a *read*,
an out-of-band callback, or a response differential — never by completing a
state-mutating write with real, irreversible consequences. Two candidates
that *looked* like they belonged in the "can't do it safely" bucket turned
out to have a safe proof and were built: prototype pollution (proof is a
cosmetic, self-healing formatting change) and price tampering (proof reads the
server's computed total without ever sending a payment instrument or
confirmation, so no charge can complete). The one genuine holdout is the race
condition: its ONLY proof is actually causing the concurrent double-spend —
mutating a real balance on whatever target Seclayer is pointed at. There is no
read-only or reversible version, so it stays a documented boundary. See
`notes` in `vulnerabilities.json`.
