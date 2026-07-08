# Seclayer — Proof & Evidence Specification (PROVEN / DETECTED)

**Status:** v0.2 draft — the gate from the session handoff (§6).
**Principle:** **Truth bomb.** Every claim on the report carries its receipt. We
remove no probes and no findings — we *add* an evidence layer so every badge is
bulletproof.
**Purpose:** Define the two truth-tiers the report ships and the exact evidence a
finding must carry to wear the top one.

> **PROVEN** — we did it, and here is the receipt (the request, the response, the
> exact bytes that prove it). Replayable, legible to a non-expert.
> **DETECTED** — we see the signal, and here is exactly what we saw. Still on the
> report, still counts, still loud. It simply doesn't wear a badge it can't back up.
>
> Both tiers are true statements. A truth bomb tells both truths precisely. Nothing
> is hidden, suppressed, or deleted.

---

## 0. The one thing to fix (everything else is addition)

Today the strong word is asserted, not demonstrated. `scoring.ts:isConfirmed()`
grants "Confirmed" whenever `confidence === "high"`, and every active finding is
created with `confidence: "high"` hardcoded (`scanner.ts:1251` RED_TEAM,
`scanner.ts:1266` API_SEC). So an active module claims proof the instant it fires,
with nothing behind the word.

That single gap is the whole risk: one false "we exploited this" on a real user's
app is permanent trust loss. **The fix is not to report less — it's to make the word
heavier.** After this, PROVEN comes with a visible, replayable exploit attached.

### What each probe catches today, and the receipt we bolt on

Every one of these **stays and keeps firing.** The right column is pure addition.

| Module | Keeps doing (unchanged) | We ADD |
|---|---|---|
| **BOLA** (`scanner.ts:854`) | GET a user endpoint, detect it returns object data. | (a) two-identity cross-tenant read that pulls **another user's real data** → PROVEN BOLA; (b) the unauth case it already catches becomes a PROVEN "Unauthenticated Access" finding with a receipt — **still critical**, just accurately named. |
| **SQLi** (`scanner.ts:693`) | Match DB error signatures. | Store the request + the erroring response, quote the DB error → receipt. |
| **Reflected XSS** (`scanner.ts:721`) | Confirm a unique token reflected unencoded. | Store the reflecting response, highlight the payload → receipt. |
| **Cmd injection / SSRF** (`scanner.ts:746`,`770`) | Match `uid=`/`gid=` or SSH banner. | Store the response, quote the command output / banner → receipt. |
| **GraphQL introspection** (`scanner.ts:813`) | Parse a real `data.__schema.types` result — **already stores `rawRequest`/`rawResponse`.** | Nothing structural; it's the model. Port its exchange into the shared bundle. |

**Key structural fact (why this is cheap):** the `Finding` type already has
`rawRequest`/`rawResponse` (`src/types.ts:23-24`). The GraphQL path already fills
them. We're generalizing an existing, shipped pattern to every probe — not building
new machinery.

---

## 1. The two tiers

### PROVEN
A finding is **PROVEN** when it carries a **stored, replayable evidence bundle**
(§2). Three clauses, each load-bearing:

1. **Stored & replayable** — the exact request(s) and response(s) that constitute the
   proof are persisted on the finding. A third party (or Carlos, six months later)
   can replay them and observe the same result.
2. **Legible to a non-expert** — the audience-defining constraint. The vibe-coder
   can't evaluate security themselves, so the bundle carries a differential a
   layperson can read: "we asked for X, we got back Y that should have been private —
   here it is." This clause is where the bomb goes off.
3. **Ownership-gated** — the action only ran because ownership was proven
   (`allowActiveProbes`, backed by `DomainVerification`). The proof reference travels
   with the finding.

### DETECTED
Everything we observe that doesn't (yet) carry a full receipt ships as **DETECTED** —
the product's existing lower tier (currently rendered "Needs Verification"). It is
**still reported, still counted, still visible**, and it shows *what we actually saw*.
DETECTED is not a punishment or a removal; it's the honest label for a real signal
whose exploit we haven't demonstrated end-to-end. Many findings are legitimately
DETECTED forever (a missing CSP header is a real gap, not an exploit) — and that's
fine. The report is strongest when both tiers are precise.

> **This is the whole wedge.** Competitors say "you probably have an IDOR." Seclayer
> says "we changed the ID, read another row, here's the row — and we only did it
> because you proved you own this." Clause 2 is what makes that sentence detonate.

*(Naming: the report renames the two badges to **PROVEN** / **DETECTED**. The
underlying `isConfirmed()`/`confirmedCount` plumbing stays; only what grants the top
tier changes — from a confidence flag to a valid receipt.)*

---

## 2. The evidence bundle (structure)

Attach a structured `ExploitEvidence` to any finding claiming **PROVEN** (a new
optional field on `Finding`, generalizing today's `rawRequest`/`rawResponse`):

```ts
interface ExploitEvidence {
  method: "differential" | "reflection" | "error-signature" | "oracle" | "introspection";

  // The requests that constitute the proof. `baseline` is the authorized/control
  // request; `attack` is the mutation. Some classes need only `attack`.
  baseline?: RawExchange;   // e.g. "read my own object" (200, my data)
  attack: RawExchange;      // e.g. "read the neighbouring object" (200, NOT my data)
  control?: RawExchange;    // negative control: same attack minus the exploit → denied

  // The single fact that earns PROVEN, quoted verbatim from `attack`
  // with a byte offset so the UI can highlight it in the raw response.
  signal: { quote: string; offsetInResponse: number; why: string };

  // One plain-English sentence a non-technical builder can read and believe.
  // "We requested order #1002 while logged in as the owner of #1001 and the
  //  server returned #1002's shipping address and email."
  demonstration: string;

  // Ownership proof this action was gated behind.
  ownership: { verificationId: string; method: "dns" | "file" | "attestation" };

  // Enough to replay: a copy-pasteable curl (secrets redacted) per exchange.
  reproduction: string;

  capturedAt: string;
}

interface RawExchange {
  request: string;   // raw HTTP request line + headers + body (secrets redacted)
  response: string;  // status line + headers + body, truncated with an explicit
                     // "[…truncated N bytes]" marker, never silently cut
  identity?: string; // which test identity issued it, e.g. "tenant-A"
}
```

Rules on the bundle:

- **Truncation is explicit.** Never silently slice a body (today API_SEC does
  `substring(0, 500) + "..."` — the marker must state how much was dropped so the
  evidence can't look complete when it isn't).
- **Secrets are redacted, structure preserved.** Redact bearer tokens/cookies to
  `Bearer ***` but keep header names and the response payload — the payload *is* the
  proof.
- **`signal.quote` must be a literal substring of `attack.response`.** A grading
  assertion: if the quote isn't found in the stored response, the bundle is invalid
  and the finding ships as DETECTED, not PROVEN.

---

## 3. Per-class contracts

Each class states: the **minimum evidence** for **PROVEN**, the **signal** that
counts, and the conditions under which it instead ships as **DETECTED** (still
reported — just without the top badge).

### 3.1 BOLA / IDOR  ← the flagship — **DECIDED: two identities earns PROVEN**

The differentiator's centre of gravity, so it gets the strictest proof.
**Authorization is inherently relational** — you can't prove an object *should have
been private* from a single request. Settled:

> **A two-identity cross-tenant read is what earns a PROVEN BOLA/IDOR.** Without two
> identities we still report what we see — as DETECTED — but only the real
> cross-tenant demonstration wears PROVEN. This makes the flagship claim *harder*,
> not softer: PROVEN BOLA means we pulled another user's actual data.

#### This probe catches two different things — we now name both

"GET `/api/v1/users/admin` returned a user object" can mean either of two real
vulnerabilities. Today's probe catches the first and *calls it the second*. We keep
both — correctly labelled:

| | **Unauthenticated access (missing authN)** | **BOLA (broken object-level authZ)** |
|---|---|---|
| Question | "Can a stranger read this at all?" | "Can user A read user **B's** object?" |
| Identities needed | zero/one + a control | **two** |
| OWASP | A01 (broken access control) | A01 / API1:2023 (BOLA) |
| Provable end-to-end with one cred? | **Yes** → PROVEN (§3.1b) | **No** → PROVEN needs two (§3.1a) |

#### 3.1a BOLA / IDOR — the two-identity PROVEN contract

- **Setup (ground-truth, not the exploit):** identity **B** reads its own object
  `X_B` → capture a `B-marker` (a value known to belong to B, e.g. B's email).
  Identity **A** reads its own object `X_A` → capture `A-marker`. Assert
  `A-marker ≠ B-marker` (genuinely distinct principals).
- **`baseline`:** A reads `X_A` → `200` + A-marker (A's normal authorized access).
- **`attack`:** A reads `X_B` → `200` **containing B-marker** (the cross-tenant read).
- **`control`:** an **unauthenticated** request to `X_B` → **`401/403`**, proving the
  resource is actually access-controlled — so A obtaining it is a real authz break,
  not merely public data.
- **PROVEN ⇔ all three hold:** baseline authorized, attack returns B-marker, control
  denied.
- **`signal`:** the `B-marker` quoted verbatim from `attack.response` — a value
  belonging to B and **absent from A's own object**. Layperson-legible proof: *"User
  A, in their own session, pulled up User B's record — here is B's email inside A's
  response. A logged-out visitor is denied, so this data is meant to be private."*

One direction (A→B) suffices for PROVEN; testing B→A too is optional and only adds
weight.

#### 3.1b Unauthenticated Access to Protected Resource — its own PROVEN finding

The thing today's probe actually catches. It **keeps its critical severity** — it
does not get weaker; it gets a receipt and an accurate name:

- **`attack`:** an **unauthenticated** request to a resource → `200` + object data.
- **`control`:** a sibling route that *does* require auth, or the resource pattern
  (`/users/<id>`, `/orders/<id>`) implying per-owner data — establishing the app
  intends this protected.
- **PROVEN ⇔** a protected-looking resource returns real object data to a request
  carrying no credentials. Title: "Unauthenticated Access to Protected Resource"
  (A01). We simply don't call it BOLA, because BOLA is the stronger cross-tenant
  claim in §3.1a.
- A **deliberately public** API (docs/route naming say so) is reported as an
  info-level note — still on the report, not dressed as a vuln.

#### 3.1c The BOLA ladder (what ships, by input — nothing dropped)

| Identities | control | attack | Ships as |
|---|---|---|---|
| 2 | denied (401/403) | returns B-marker | **PROVEN BOLA** (critical) — receipt attached |
| 2 | denied | A's own data / 403 / no B-marker | **Authorization held** — reported as a *passing* evidence note (a win worth showing) |
| 2 | **succeeds** | returns data | **PROVEN Unauthenticated Access** (§3.1b) or public-endpoint note |
| 1 | denied | endpoint returns object data | **DETECTED** — "returns object data; add a second test identity to prove cross-tenant access" |
| 0 (unauth) | protected pattern | returns protected data | **PROVEN Unauthenticated Access** (§3.1b) — critical |
| 0 (unauth) | — | 401/403 / no data | reported as an **Authorization held** note |

Every row produces output. The only change from today is that the *cross-tenant BOLA
claim* wears PROVEN only when we actually demonstrated it — while the unauth exposure
the probe already finds stays a PROVEN critical.

#### Scan-input shape this adds

```ts
interface BolaIdentity {
  label: string;        // "tenant-A"
  authHeader: string;   // this identity's credential
  ownResource: string;  // a path to an object it owns, e.g. "/api/v1/orders/1001"
  ownMarker?: string;   // optional: a value the caller knows is unique to its data
}
interface ScanOptions {
  allowActiveProbes?: boolean;                     // still required (ownership gate)
  bolaIdentities?: [BolaIdentity, BolaIdentity];   // two → unlocks PROVEN cross-tenant BOLA
}
```

`allowActiveProbes` (ownership proven) stays mandatory; two identities is an
**additional** unlock layered on top, never a replacement.

#### Testbed consequence

Seed the testbed with **two users, each owning a distinct row**, plus a locked
reference (401 unauth) and a **legitimately-public endpoint** as a false-positive
control fixture. The two-user fixture lets the flagship claim be exercised; the
public fixture proves we never false-PROVE. Both are required fixtures.

### 3.2 SQL Injection

- **PROVEN needs:** `attack` (the injected request) + its full `response`. Prefer a
  differential (`baseline` benign value → normal page, vs `attack` metacharacter → DB
  error or changed row set).
- **Signal:** a DB error signature (the existing `sqlErrorSig` set) quoted from
  `attack.response`, **or** a boolean-oracle differential (`id=1 AND 1=1` returns the
  row, `id=1 AND 1=2` doesn't).
- **Ships as DETECTED when:** the error string also appears in `baseline` (static
  page content), matches inside an HTML error page the app always serves, or the
  response is the SPA shell (`looksLikeHtml`). Still reported — as a detected signal.

### 3.3 Reflected XSS

- **PROVEN needs:** `attack` carrying a unique nonce payload + the `response` that
  reflects it. (Today's nonce strategy is already correct — it just needs to be
  *stored*.)
- **Signal:** the exact `<script>NONCE</script>` / `<svg/onload=NONCE>` payload found
  verbatim and **unencoded** in `attack.response`, quoted with offset.
- **Ships as DETECTED when:** the payload comes back HTML-entity-encoded
  (`&lt;script&gt;` — the app *is* escaping), or reflects only into an
  attribute/JS-string/comment/`<textarea>` context where execution isn't shown.

### 3.4 OS Command Injection

- **PROVEN needs:** `attack` + `response` containing command-execution output.
- **Signal:** a value that could only come from executing the injected command
  (`uid=…gid=…` from `; id`). Prefer a nonce arithmetic oracle (`; expr 7331 + 42`
  → `7373`) so the proof can't be a coincidental page string.
- **Ships as DETECTED when:** `uid=`/`gid=` also appears in `baseline` (page
  content), or the only signal is timing (timing-only stays DETECTED).

### 3.5 SSRF

- **PROVEN needs:** `attack` + `response` proving the server fetched an
  attacker-chosen internal resource.
- **Signal:** internal-only content in `attack.response` (SSH banner, cloud-metadata
  JSON) the public target couldn't otherwise return. Best: a unique out-of-band
  callback token to a listener we control, proving the fetch originated server-side.
- **Ships as DETECTED when:** the "banner" is reflected from the request rather than
  fetched, or the target legitimately proxies public URLs and returned public content.

### 3.6 GraphQL Introspection

- **PROVEN needs:** already correct — `rawRequest`/`rawResponse` with a parsed
  `data.__schema.types` array. Port it into the bundle format.
- **Signal:** `data.__schema.types` is a non-empty array in `attack.response`.
- **Ships as DETECTED when:** the response is an error mentioning `__schema`, or
  introspection returns an empty/`null` schema. **Severity note (open decision #2):**
  exposed introspection is a disclosure, so it's PROVEN-but-`high`, not `critical` —
  the schema *is* the evidence.

---

## 4. What separates PROVEN from DETECTED (false-positive-prevention framework)

A finding ships as **DETECTED** (still reported, with what we saw) rather than
**PROVEN** when any hold — none of these remove the finding, they choose its badge:

1. **No stored `attack.response`** — nothing to show, nothing to replay.
2. **`signal.quote` is not a literal substring of the stored response** — the proof
   doesn't actually contain the thing we claim proves it. (Automatable assertion.)
3. **The evidence also appears in `baseline`/`control`** — we haven't isolated the
   vulnerability from normal behaviour.
4. **Response is the SPA shell** (`looksLikeHtml`) where real payload/data was
   expected.

One hard exception: **no ownership-proof reference** means the active action should
never have run — that's a pipeline error, not a badge choice.

`isConfirmed()` is redefined to check the **presence and validity of the evidence
bundle**, not `confidence === "high"`. Confidence becomes an input to DETECTED-tier
ranking, never the thing that grants PROVEN.

---

## 5. Code deltas (all additive — no probe removed)

1. **`Finding` type** — add `evidence?: ExploitEvidence` (generalizes the existing
   `rawRequest`/`rawResponse`, which stay populated during transition — open #4).
2. **`scanner.ts` RED_TEAM probes** — keep every probe; additionally store the
   request + response + quoted signal as an `ExploitEvidence`. Stop *relying on* a
   hardcoded `confidence:"high"` to mean proof.
3. **`scanner.ts` BOLA probe** — keep the current detection; additionally (a) build
   the §3.1b unauthenticated-access finding with a receipt (stays critical), and
   (b) when `bolaIdentities` are supplied, run the §3.1a cross-tenant differential →
   PROVEN BOLA. One credential → the cross-tenant claim ships DETECTED per §3.1c.
4. **Two-identity support** — `ScanOptions` gains `bolaIdentities?: [BolaIdentity,
   BolaIdentity]`. Cross-read each identity's resource as the other. Layered on top
   of the existing `allowActiveProbes` ownership gate.
5. **`scoring.ts:isConfirmed()`** — grant the top tier on a valid bundle (§4), not on
   the confidence flag.
6. **Report UI** (`ReportViewer.tsx`) — render the two badges as **PROVEN /
   DETECTED**; on PROVEN, show `demonstration` + the highlighted `signal.quote` inside
   the raw exchange. This is where the truth bomb actually lands for the user.

---

## 6. How the planted testbed grades this

The testbed is the **only** instrument with known ground truth, so it is the sole
gate for the word PROVEN. Rubric:

- **Every planted vuln** ships with an *expected receipt* (the signal that must
  appear). The harness passes only if a PROVEN finding exists **and** its
  `signal.quote` matches the expected proof. → proves **"PROVEN means demonstrated."**
- **A two-identity BOLA fixture** (users A and B, each owning a row) — without it the
  flagship claim can't be exercised.
- **A clean control surface** (endpoints with no planted vuln, incl. a *legitimately
  public* user endpoint) must yield **zero PROVEN** findings. This is the in-testbed
  version of the false-positive gate the 20 real apps enforce at scale.

Only once the testbed shows *catch-what-we-planted* **and** *zero-false-PROVEN* does
the definition earn the right to run against the scrubbed 20 and 100.

---

## 7. Decisions

1. ~~**Two-identity BOLA**~~ — **DECIDED (2026-07-07):** two owned test identities earn
   a PROVEN cross-tenant BOLA. Nothing is removed: with one/zero identities we still
   report what we see (DETECTED, or a PROVEN "Unauthenticated Access" finding that
   keeps critical severity). Contract in §3.1.
2. ~~**Confirmed/Inferred vs additive**~~ — **DECIDED (2026-07-07):** additive, keep
   every probe; two tiers rendered **PROVEN / DETECTED**, both shipped and visible.

Open:

3. **Severity of introspection** — PROVEN-but-`high` (disclosure), not `critical`?
4. **Collaborator infra for SSRF** — stand up an out-of-band callback listener, or
   accept internal-content-reflection as the only PROVEN SSRF signal for v1? (Without
   it, reflected-only cases ship DETECTED.)
5. **Field migration** — keep `rawRequest`/`rawResponse` alongside `ExploitEvidence`
   through the transition (proposed), or cut over in one change?
```
