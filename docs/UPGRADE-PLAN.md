# Seclayer — Refactor & Security Upgrade Plan

Two tracks: (1) a structural refactor toward small, single-responsibility modules,
and (2) a security roadmap built by thinking like the attackers who target
inexperienced "vibe coder" apps. The refactor makes the second track safe to move
fast on.

---

## Part 1 — Codebase refactor

**Principle:** split by *responsibility*, not to hit a number. ~200 lines is a
smell, not a law. Cohesive data tables and one-job modules can be longer; tangled
multi-purpose files should split even under 200. Tests (`npm test`, 200 passing)
stay green after each step — refactor one module, re-run, commit.

### Files over 200 lines and the proposed split

| File | LOC | Plan | Priority |
|------|----:|------|:--------:|
| `server/templates.ts` | 1462 | **Data, not logic.** Move to `server/templates/` — one module per category (exposed-panels, config/backup, actuators, wp, takeover, generic), re-exported by an `index.ts`. Improves navigation; don't shrink for its own sake. | Med |
| `server/db.ts` | 501 | Split the repository by domain: `db/scans.ts`, `db/users.ts`, `db/apiKeys.ts`, `db/domains.ts`, `db/oob.ts`, `db/monitors.ts`, `db/suppressions.ts`; a thin `db.ts` composes them over the shared connection. | **High** |
| `server/paramFuzzer.ts` | 367 | Extract each per-class detector into `server/fuzz/` (`sqli.ts`, `xss.ts`, `ssti.ts`, `lfi.ts`, `openRedirect.ts`, `crlf.ts`) sharing one small helper; `paramFuzzer.ts` keeps only budget/ranking/loop orchestration. *(Recently grown by the aggressive tier — do first.)* | **High** |
| `src/pages/Dashboard.tsx` | 316 | Extract `useScanLauncherConfig` hook (per-URL memory + persistence) and move billing + tab routing into subcomponents. *(Recently grown — do first.)* | **High** |
| `server/findings.ts` | 297 | Split per-category builders into `server/findings/` (surface, easm, headers, cookies, sast, sca, exposedPaths, redteam, apisec); `findings.ts` composes → dedupes → scores. | **High** |
| `src/hooks/useSeclayer.ts` | 294 | Split into `useAuthSession`, `useScans`, `useApiKeys`, `useBilling`; `useSeclayer` composes them. | Med |
| `src/pages/ReportViewer.tsx` | 247 | Extract the meta/score header and the not-complete state into subcomponents. | Med |
| `src/types.ts` | 234 | Split into `types/scan.ts`, `types/finding.ts`, `types/evidence.ts`, `types/account.ts`; re-export from `types.ts` (no import churn). | Med |
| `server/ssrf.ts` | 229 | Separate concerns: `ssrf/guard.ts` (IP/DNS validation), `ssrf/fetch.ts` (guardedFetch/safeFetch), `ssrf/devAllow.ts` (allowlist). | Med |
| `server/routes/account.ts` | 225 | Split into `routes/account.ts` (profile/webhook), `routes/billing.ts` (credits/checkout), `routes/monitors.ts`. | Med |
| `server/crawler.ts` | 225 | Extract link/form/JS-endpoint extraction into `crawler/extract.ts`; keep BFS + budget in `crawler.ts`. | Low |
| `src/components/dashboard/MonitoringTab.tsx` | 224 | Extract the schedule form and the monitor row into subcomponents. | Low |
| `server/deepseek.ts` | 212 | Extract response normalization + evidence-reattach into `deepseek/normalize.ts`. | Low |
| `server/scoring.ts` | 207 | Borderline; split posture-derivation from tier classification only if it reads cleaner. | Low |
| `src/components/dashboard/ScanLauncher.tsx` | 202 | Extract the BOLA-identities block and the advanced/aggressive block into subcomponents. | Low |
| `server/render.ts` | 201 | Borderline; cohesive headless-render module — likely leave as-is. | Skip |

**Sequencing:** start with the four **High** items I recently inflated or that
carry the most logic (`paramFuzzer`, `Dashboard`, `findings`, `db`), tests green
after each. The **Low/Skip** ones are marginal — do them only if they genuinely
read better split.

---

## Part 2 — Security upgrade roadmap ("5 steps ahead")

### Who we're defending, and against whom
The target user ships fast with AI codegen and low security awareness. Typical
stack: React/Next.js + a BaaS (Supabase/Firebase) + Stripe + an LLM API on
Vercel/Netlify. The attackers are automated and relentless: bundle-grepping bots,
credential stuffers, IDOR fuzzers, BaaS-misconfig scanners, and increasingly
AI-driven attack tooling. **Where vibe coders bleed today:** secrets hardcoded in
the client bundle, BaaS access rules left open, missing authorization, and
under-tested AI endpoints. Those are the frontier — and where we must lead.

### Phase 1 — Now (biggest gaps for this audience, highest ROI)
1. **Client-bundle & source-map secret scanning.** Fetch every JS bundle + any
   exposed `.map`, extract API keys, tokens, Firebase/Supabase configs, private
   keys, JWTs. *Attacker POV: the first thing a bot does is grep your bundle.*
2. **BaaS misconfiguration probes.** Supabase RLS-off (anon key reads a table
   unauthenticated), Firebase open security rules, public storage buckets,
   reachable `/rest/v1/`. *The dominant vibe-coder backend; misconfig is instant,
   total data exposure.*
3. **Broken access control, in depth.** BFLA (function-level authz), IDOR sweeps
   over numeric/UUID ids, mass assignment (`role:admin`, `isAdmin:true`), and
   missing auth on state-changing endpoints. *OWASP #1; the flaw AI codegen omits.*
4. **JWT weaknesses.** `alg:none`, weak/guessable HS256 secret, missing/ignored
   `exp`, unverified signature. *A one-line auth bypass when wrong.*
5. **Blind SQLi (time + boolean).** Closes the error-suppressed gap the current
   error-signature probe misses.

### Phase 2 — Next (modern & AI-era surface)
6. **AI/LLM app attacks.** Detect LLM-backed endpoints; test prompt injection,
   system-prompt leakage, unbounded/expensive generation, and LLM-mediated authz
   bypass. *A brand-new surface these apps ship and rarely test.*
7. **Authenticated + stateful scanning.** Session-aware crawl, multi-step flows,
   CSRF-token handling — so the *authenticated* attack surface is actually reached.
8. **API-first testing.** Discover OpenAPI/Swagger/GraphQL schemas → fuzz every
   declared operation, not just crawled params.
9. **Business-logic probes (safe).** Negative/oversized quantities, price/coupon
   tampering, workflow step-skipping — non-destructive, oracle-proven.
10. **CSRF & session hardening.** Missing anti-CSRF on state-changing routes; weak
    cookie/session flags (partially covered).

### Phase 3 — Later (depth, breadth, staying ahead)
11. **Anti-evasion & accuracy.** WAF fingerprinting + adaptive/encoded payloads;
    drive down false negatives (an attacker will find what we miss).
12. **Supply chain.** Transitive SCA, typosquat/dependency-confusion heuristics,
    exposed lockfiles, risky `postinstall` scripts.
13. **Client-side depth.** DOM XSS via headless-by-default, `postMessage` abuse,
    prototype pollution, source-map-driven backend mapping.
14. **Continuous & pre-deploy.** CI / pre-publish gate, scheduled re-scans
    (exists), regression diffing, alerting (exists).
15. **Cloud/infra.** Metadata SSRF (partial), open S3/GCS buckets, exposed
    dashboards/actuators (templates exist), TLS/cert posture.

### Cross-cutting — the vibe-coder moat (UX)
- **Plain-English what/why/impact/fix** (exists) + **framework-aware** fix prompts
  (detect the stack, tailor the remediation).
- **Ruthless prioritization** for non-experts: "fix these 3 today."
- **One-click fix prompts** (exists) → optional **auto-generated hardening PRs**.

### Don't become the weapon — scanner-as-a-target hardening
Every offensive capability stays: **ownership-verified**, **non-destructive**
(oracle/OOB/differential proofs — no writes, deletes, or DoS), **rate-limited**,
**scoped**, with a **kill switch**, and **secrets in evidence always redacted**.
More power ⇒ stricter gates, never looser.

---

## Suggested order of operations
1. Refactor the four **High** modules (safe, unblocks fast iteration).
2. Ship **Phase 1** security upgrades (secret-bundle scan → BaaS misconfig →
   access-control depth → JWT → blind SQLi), each with a PROVEN receipt and a
   test-target case in `vulnerable-app.mjs` + `validate-probes.mjs`.
3. Then Phase 2, then Phase 3.
