# Scan results — measured runs, per URL

What Seclayer returned when pointed at thirty real sites, with the score and
grade each produced.

**68 runs, 38 hosts, passive.** Two rounds, both scanned independently of
SecScan — the two products share targets, not code.

The most recent round is the one to read:
**[`scan-results/2026-09-10-rerun/`](scan-results/2026-09-10-rerun/SCAN-RESULTS.md)**
— 38 targets, a page per site with every finding and how it was verified.
SecScan scanned the same 38 the same night, so the two engines are directly
comparable for the first time.

**33 sites graded:** A 10 · B 6 · C 8 · D 7 · F 2 — mean 79.0, against 79.9 in
round 1. `letsencrypt.org` was unreachable (`fetch failed`), transient.

Raw output is committed at `scan-results/2026-09-08-corpus-30.json`, so each
row can be checked rather than taken on trust. Cookie values were already
redacted by the engine itself.

## How to read the score

`server/scoring.ts` is the single source: every consumer — executive score,
pillar cards, PDF export, suppression read-model — derives from it, so they
cannot drift apart.

**Higher is better.** 100 is clean. Only critical/high/medium/low deduct; a site
whose findings are all info notices scores a true 100. The score is the lower of
a deduction total and a confirmed-severity ceiling, floored above zero so the UI
gauge always renders.

`gradeForScore`: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F below.

> SecScan runs the opposite scale (0 = clean, A ≤ 10). The two numbers are not
> comparable. SecScan's results live in that repo at
> `artifacts/api-server/scripts/SCAN-RESULTS.md`.

---

## The corpus

| Host | Score | Grade | Crit | High | Med | Low | Info | Findings | Secs |
|---|---|---|---|---|---|---|---|---|---|
| github.com | 73 | **C** | 0 | 0 | 2 | 1 | 3 | 6 | 8.4 |
| gitlab.com | 80 | **B** | 0 | 0 | 2 | 1 | 2 | 5 | 14.5 |
| www.npmjs.com | 100 | **A** | 0 | 0 | 0 | 0 | 1 | 1 | 7.5 |
| stackoverflow.com | 93 | **A** | 0 | 0 | 1 | 0 | 1 | 2 | 5.7 |
| vercel.com | 75 | **C** | 0 | 0 | 2 | 2 | 3 | 7 | 24.4 |
| www.cloudflare.com | 65 | **D** | 0 | 0 | 1 | 4 | 2 | 7 | 14.4 |
| www.mozilla.org | 100 | **A** | 0 | 0 | 0 | 0 | 3 | 3 | 11.9 |
| www.digitalocean.com | 93 | **A** | 0 | 0 | 1 | 0 | 3 | 4 | 18.9 |
| www.fastly.com | 73 | **C** | 0 | 0 | 3 | 1 | 3 | 7 | 16.8 |
| letsencrypt.org | 100 | **A** | 0 | 0 | 0 | 0 | 3 | 3 | 6.1 |
| www.bbc.co.uk | 100 | **A** | 0 | 0 | 0 | 0 | 3 | 3 | 9.5 |
| www.nytimes.com | 45 | **F** | 0 | 0 | 7 | 0 | 3 | 10 | 15.9 |
| www.theguardian.com | 70 | **C** | 0 | 0 | 4 | 0 | 2 | 6 | 9.2 |
| www.reuters.com | 85 | **B** | 0 | 0 | 2 | 0 | 2 | 4 | 3.8 |
| apnews.com | 85 | **B** | 0 | 0 | 2 | 0 | 3 | 5 | 10.6 |
| www.shopify.com | 63 | **D** | 0 | 0 | 5 | 0 | 2 | 7 | 8.6 |
| stripe.com | 93 | **A** | 0 | 0 | 1 | 0 | 3 | 4 | 10.4 |
| www.etsy.com | 63 | **D** | 0 | 0 | 5 | 0 | 2 | 7 | 10.6 |
| www.ebay.com | 70 | **C** | 0 | 0 | 4 | 0 | 3 | 7 | 10.1 |
| www.amazon.co.uk | 40 | **F** | 0 | 0 | 6 | 0 | 3 | 9 | 15.1 |
| www.gov.uk | 100 | **A** | 0 | 0 | 0 | 0 | 3 | 3 | 24.1 |
| www.wikipedia.org | 70 | **C** | 0 | 0 | 4 | 0 | 3 | 7 | 4.9 |
| archive.org | 88 | **B** | 0 | 0 | 1 | 1 | 2 | 4 | 7.0 |
| european-union.europa.eu | 93 | **A** | 0 | 0 | 1 | 0 | 2 | 3 | 16.2 |
| www.nasa.gov | 93 | **A** | 0 | 0 | 1 | 0 | 3 | 4 | 14.5 |
| www.notion.so | 70 | **C** | 0 | 0 | 4 | 0 | 3 | 7 | 12.3 |
| www.figma.com | 100 | **A** | 0 | 0 | 0 | 0 | 2 | 2 | 19.8 |
| slack.com | 70 | **C** | 0 | 0 | 4 | 0 | 3 | 7 | 6.9 |
| www.dropbox.com | 85 | **B** | 0 | 0 | 1 | 0 | 3 | 4 | 8.8 |
| zoom.us | 63 | **D** | 0 | 0 | 5 | 0 | 2 | 7 | 9.4 |
**Distribution:** A 11 · B 5 · C 8 · D 4 · F 2 — mean 79.9, median 85.
Range 40 (amazon.co.uk) to 100 (six sites).

## Reading the spread

**Six perfect scores.** npmjs, mozilla.org, letsencrypt, bbc.co.uk, gov.uk and
figma returned nothing but info notices. That is the shape a correct engine
produces against a well-run site, and it is only reachable because info carries
no deduction.

**Zero critical, zero high, across all thirty.** Every deduction in this table
came from medium and low. Passive observation of a healthy site should not be
able to manufacture a critical — if one appears here without the target having
changed, suspect the engine first.

**The two Fs are cookie volume, not weakness.** nytimes.com (45) and
amazon.co.uk (40) both run large ad-tech cookie sets; each cookie missing a flag
is its own medium. Worth knowing before reading an F here as "this site is
broken" — see `server/cookieClassify.ts`, which is what keeps known
ads/analytics cookies from being read as session cookies.

**Seclayer grades harder than SecScan on the same sites.** github.com is C here
and B there; gov.uk is A in both. Different weighting, different scale, and no
conclusion should be drawn from the gap in either direction.

## What the 2026-09-10 round found

**A scan that was blocked scores 100 — the top of the scale.**

`compileStaticFindings` withholds every finding read from a challenge page,
which is right, and `interceptedFinding` tells the reader plainly:

> THIS IS NOT A CLEAN RESULT: it is an incomplete one, and the score reflects
> only what could still be observed.

Then `scoreFindings(withheld)` runs over a set that is entirely info notices,
nothing deducts, and the result is **100/A** — for `stackoverflow.com`,
`ebay.com`, `etsy.com` and `reuters.com`, none of whose pages were ever seen.
Indistinguishable, on the page, from the genuine 100s that `mozilla.org` and
`gov.uk` earned.

SecScan has the identical defect from the opposite end of its inverted scale:
`computeRiskScore` returns **0**, its best score, for the six sites it was
blocked on.

The suppression itself is careful and the comment above it is right about why.
What was missed is that the score is also a claim about the target, and it was
left to fall out of an empty finding list rather than being decided.

The tables in `scan-results/2026-09-10-rerun/` mark these sites and exclude them
from the mean, so the report is honest — but the product still shows 100/A.
Not yet fixed: it is a scoring-semantics decision, not a patch.

## Caveats

Scanner state is 2026-09-08 — this predates the challenge-page port
(`server/challengePage.ts`), the CSP report-only detection, the HSTS preload
list and the `strictNullChecks` pass. Re-run before treating any row as current.

Detection self-check, separate from this corpus:

```
npx tsx scripts/detection-check.ts
```
