# Verification runbook

How to prove each change from the 2026-09-07 work still holds. Every command
here was actually run, and the stated expectations are what was actually
observed rather than what ought to happen.

Run the relevant section after any deploy touching that area. A check that
cannot fail is not a check, so each one states its failure signature.

---

## 1. Postgres, not SQLite

**What changed.** seclayer.app ran on SQLite on a single attached volume, which
capped it at exactly one instance — Railway cannot share a volume across
replicas. It now runs on its own Postgres in the `seclayer-app` project.

```
railway variables --service seclayer-app --kv | grep -c '^DATABASE_URL='
curl -s https://seclayer.app/api/system/health
```

Expect `DATABASE_URL` present, and `checks.database: ok`.

**Failure signature.** `createDb()` falls back to SQLite whenever `DATABASE_URL`
is absent. The app still boots and looks perfectly healthy while serving the
stale pre-migration file — so check for the VARIABLE, not just a green health
endpoint.

**Rollback.** Remove `DATABASE_URL` and redeploy. The detached volume still
holds the pre-migration database, and copies are in
`~/seclayer-rollback-2026-09-07/` with a README.

---

## 2. Three replicas actually serving

```
for i in $(seq 1 40); do
  curl -s "https://seclayer.app/api/system/health?cb=$RANDOM$i" |
    python -c "import sys,json;print(json.load(sys.stdin).get('instance'))"
done | sort | uniq -c
```

Expect three distinct instance ids. Sample ~40 times; smaller samples regularly
miss one.

**Why the id exists.** Uptime cannot separate replicas that started together —
probing it during a scale-up returned 66–73s, which is just the clock advancing,
not four processes.

**Scaling gotcha.** Set replicas in the Railway dashboard, on the EXISTING
region row. `railway scale` cannot address the legacy `sfo` region, so it adds a
second region instead, and a service spanning two regions fails to schedule:
two deploys died in under 15s with no container ever starting.

---

## 3. Rate limits shared across replicas

The sharpest check here, because the failure is otherwise invisible: with a
per-process store, three replicas each enforce their own copy and the effective
limit silently becomes 3×.

Submit the same mailbox nine times (fresh address each run):

```
EMAIL="probe-$RANDOM@seclayer.test"
for i in $(seq 1 9); do
  curl -s -X POST https://seclayer.app/api/auth/request-link \
    -H "Content-Type: application/json" -d "{\"email\":\"$EMAIL\"}"
  echo
done
```

Expect exactly 5 successes, then errors. Observed: 5 ok, 4 rejected.

**Failure signature.** Around 15 succeed. That means the in-memory store is
active — check the boot log for `[rateLimit] Shared database-backed store`.

Use a fresh mailbox each run: the limiter is keyed on the address (5/hour) as
well as on IP, deliberately, so a client with rotating source IPs cannot
multiply its own allowance.

---

## 4. Scan queue distributes, and claims exactly once

Submit 4 scans from the dashboard, then:

```
railway logs --service seclayer-app -d --lines 300 |
  grep -oE "\[[0-9a-f]{8}\] claimed scan_[0-9a-f]+" > /tmp/claims.txt

grep -oE "^\[[0-9a-f]{8}\]" /tmp/claims.txt | sort | uniq -c          # spread
grep -oE "scan_[0-9a-f]+" /tmp/claims.txt | sort | uniq -c | awk '$1>1'  # dupes
```

Expect claims across 2–3 distinct workers, and the last command to print
**nothing**.

**The duplicate check is the one that matters.** A scan claimed twice means
doubled cost, duplicate probes aimed at the customer's target, and two writers
racing on one scan row. Spread is a latency optimisation; exactly-once is
correctness.

**Observed progression** — worth recording, because two "fixes" changed nothing:

| Claim strategy | Split of 4 scans |
|---|---|
| Greedy fill | 3/1/0 |
| One per tick | 3/1/0 (no change — wrong mechanism) |
| Load-aware | 2/1/1 |

One-per-tick only helps when scans queue at the same instant. Real submissions
arrive seconds apart, so each goes to whichever worker's timer fires next, and a
worker whose phase leads wins every race regardless of how loaded it already is.
Claiming had to become load-aware, not less greedy.

---

## 5. Periodic work fires once, not once per replica

Both were read-then-write races that only appear with more than one instance.

```
npx tsx --test server/digestClaim.test.ts server/monitorClaim.test.ts
```

Each suite fires three simultaneous claims and asserts exactly one wins.

**Do not "simplify" the monitor lease into `nextRun`.** That column carries
scheduling decisions the tick has not made yet: a target skipped for want of
credits keeps its due time so it retries on the next tick, while an unsafe URL
defers a whole cadence. Claiming through it collapses both and silently drops
the retry. Four existing tests catch this — it was tried, and reverted.

---

## 6. Crash recovery does not kill other replicas' scans

```
npx tsx --test server/scanLease.test.ts
```

`recoverStuckScans` used to fail and refund EVERY in-flight scan at boot, with
no notion of ownership. Correct on exactly one instance; on three, any replica
restarting destroyed the other two's work and told those users their scans had
been interrupted.

Scans now carry a lease refreshed every 30s, and only leases older than 5
minutes are swept.

**Untested in production.** A replica dying mid-scan and another reclaiming it
after expiry is covered by tests, but has never been induced live.

---

## 7. Google sign-in

```
curl -sI https://seclayer.app/ | grep -i cross-origin-opener-policy
```

Expect `same-origin-allow-popups`. **Never `same-origin`** — that severs the GIS
popup from its opener, so the credential can never be handed back. The flow
hangs with no error on either side: the server log shows `/api/auth/providers`
and then nothing, because `POST /api/auth/google` is never sent. The absence of
that request is the diagnostic.

**A stale tab keeps the old behaviour.** COOP fixes a document's browsing
context group at load time, so a tab opened while the header was wrong stays
broken however many times you redeploy. Close every tab, or use incognito.

---

## 8. Backups

```
railway postgres pitr status --service Postgres
```

Expect `Status: enabled`, `Bucket wired: yes`.

`backupTo` is a deliberate no-op on Postgres, and the worker used to log
`[backup] Wrote snapshot <name>` every 24h for a file that never existed — a
backup story that read as healthy while nothing whatsoever was being backed up.
It now says so plainly and cancels its own timer.

---

## 9. DeepSeek fix prompts reach users

No external symptom; open a report. The per-finding fix prompt should read as
target-specific prose naming the detected stack, not the generic template.

The static fallback opens with this verbatim line:

> You are a senior application security engineer with full write access to this

If that exact sentence appears, the model's prompt was discarded and the
fallback shipped.

Watch too for the degrade that used to be silent:

```
railway logs --service seclayer-app -d --lines 500 | grep "no report content"
```

`finish_reason=length` means reasoning consumed the whole token budget before
any JSON was emitted. Before this logging existed, that path returned a local
summary and wrote nothing at all — which is why "the AI report isn't working"
could not be confirmed or ruled out from outside.

---

## Concurrency cap

`MAX_CONCURRENT_SCANS=6` per instance, 18 fleet-wide, set explicitly on the
service so it is a decision rather than a default.

**It is a reasoned extrapolation, not a measured limit.** Peak observed was 0.53
vCPU and 1.01 GB against limits of 8 vCPU / 8 GB — but only ever with 3
concurrent scans per worker. Memory is the binding constraint (Chromium), and an
OOM kills every scan on that instance, not only the one that caused it.

```
railway metrics --service seclayer-app --since 24h
```

If peak memory on a replica approaches ~6 GB, drop to 4. It is an env var — no
code, no deploy.

**A single client cannot load-test this.** `/api/mcp/scan` is limited to 5/min
per IP and `/api/scans` to 10/min, both deliberately ("heavy scans to exhaust
the single Node process and starve every other user's scans"). Bursting 20 scans
from one machine returns 429 — that is the app working, not a fault. 18
concurrent is only reachable across many distinct users.
