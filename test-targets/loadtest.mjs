// Scan load-test harness — measures throughput, queue latency and the
// concurrency actually achieved, instead of inferring them from config.
//
// The capacity work before this was arithmetic: median scan duration times
// configured concurrency. That is a hypothesis, not a measurement. This submits
// a real burst and records what happens, which is the only way to find the
// bottleneck rather than guess at it.
//
// ── Safety ──
// Scans are pointed at a LOCAL target you control (test-targets/hardened-app.mjs
// by default). Pointing 100 concurrent scans at somebody else's site is an
// attack, and the SSRF guard would refuse loopback anyway without the dev
// allow-list. --target is accepted so the harness can aim at a different local
// fixture, and it refuses a non-loopback host unless --i-own-this-target is
// passed.
//
// ── What it measures ──
//   submitted → started    queue wait (the number a user actually feels)
//   started   → completed  execution time
//   concurrency            how many scans were in-flight at each sample, so you
//                          can see whether the configured cap is really reached
//   memory                 process RSS, sampled through the run, to find the
//                          per-scan cost that decides how far concurrency can go
//
// Usage:
//   node test-targets/hardened-app.mjs 4101 &
//   node test-targets/loadtest.mjs --count 100 --base http://127.0.0.1:3100
//
// Options:
//   --count N        how many scans to submit (default 100)
//   --rate N         submissions per second (default 0 = all at once)
//   --base URL       the Seclayer instance (default http://localhost:3000)
//   --target URL     what to scan (default http://127.0.0.1:4101)
//   --users N        distinct signed-in users to simulate (default = --count,
//                    i.e. one scan each, which is the realistic launch shape).
//                    --users 1 instead models a single client hammering the API.
//   --email ADDR     harness account prefix (default loadtest@seclayer.test)

const args = process.argv.slice(2);
const opt = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
};
const flag = (name) => args.includes(`--${name}`);

const COUNT = Number(opt("count", "100"));
const RATE = Number(opt("rate", "0"));
const BASE = opt("base", "http://localhost:3000").replace(/\/+$/, "");
const TARGET = opt("target", "http://127.0.0.1:4101");
const EMAIL = opt("email", "loadtest@seclayer.test");
// Default one user per scan. "Can we handle 100 users" and "can one client fire
// 100 scans" are different questions with different answers, and conflating
// them is how a per-IP rate limit gets mistaken for a capacity ceiling.
const USERS = Math.max(1, Number(opt("users", String(COUNT))));

const LOOPBACK = /^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d+)?/i;
if (!LOOPBACK.test(TARGET) && !flag("i-own-this-target")) {
  console.error(
    `Refusing to aim ${COUNT} scans at ${TARGET}.\n` +
      "That is a non-loopback host. Point this at a local fixture, or pass " +
      "--i-own-this-target if it is genuinely yours.",
  );
  process.exit(2);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const pct = (sorted, p) =>
  sorted.length ? sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))] : 0;
const fmt = (ms) => (ms / 1000).toFixed(1) + "s";
const pad = (s, n) => (String(s) + " ".repeat(n)).slice(0, n);

async function signIn(address) {
  const req = await fetch(`${BASE}/api/auth/request-code`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: address }),
  });
  const body = await req.json().catch(() => ({}));
  if (!body.devCode) {
    throw new Error(
      `request-code returned no devCode for ${address}, so the harness cannot sign in. ` +
        "Run the instance without an email provider (ALLOW_MISSING_EMAIL_PROVIDER=true).",
    );
  }
  const verify = await fetch(`${BASE}/api/auth/verify-code`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: address, code: body.devCode }),
  });
  const cookie = (verify.headers.getSetCookie?.() ?? []).map((c) => c.split(";")[0]).join("; ");
  if (!cookie) throw new Error(`verify-code returned no session cookie (HTTP ${verify.status})`);
  return cookie;
}

// Sign in every simulated user up front, so the burst measures scanning rather
// than authentication. Sequential: the sign-in path has its own rate limits and
// tripping those would measure the wrong thing again.
async function signInAll(n) {
  const [local, domain] = EMAIL.split("@");
  const cookies = [];
  for (let i = 0; i < n; i++) {
    cookies.push(await signIn(n === 1 ? EMAIL : `${local}+${i}@${domain}`));
    if ((i + 1) % 25 === 0) console.log(`  signed in ${i + 1}/${n}`);
  }
  return cookies;
}

async function main() {
  console.log(`\nLoad test — ${COUNT} scans of ${TARGET} via ${BASE}`);
  console.log(RATE > 0 ? `Submitting at ${RATE}/s\n` : "Submitting all at once\n");

  console.log(`Signing in ${USERS} user${USERS === 1 ? "" : "s"}…`);
  const cookies = await signInAll(USERS);
  console.log("");

  // Confirm the target is actually up. A burst against a dead fixture measures
  // nothing but error handling, and every scan would "succeed" instantly.
  try {
    const probe = await fetch(TARGET, { signal: AbortSignal.timeout(5000) });
    if (!probe.ok) throw new Error(`HTTP ${probe.status}`);
  } catch (err) {
    console.error(`Target ${TARGET} is not reachable (${err.message}). Start it first.`);
    process.exit(2);
  }

  const scans = new Map(); // id -> { submitted, started, completed, status }
  const t0 = Date.now();

  // ── Submit ────────────────────────────────────────────────────────────────
  let submitFailures = 0;
  for (let i = 0; i < COUNT; i++) {
    fetch(`${BASE}/api/scans`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: cookies[i % cookies.length] },
      body: JSON.stringify({ url: TARGET }),
    })
      .then(async (r) => {
        const j = await r.json().catch(() => ({}));
        const id = j?.scan?.id ?? j?.id;
        if (!r.ok || !id) {
          submitFailures++;
          if (submitFailures <= 3) console.log(`  submit rejected: HTTP ${r.status} ${JSON.stringify(j).slice(0, 90)}`);
          return;
        }
        scans.set(id, { submitted: Date.now(), started: null, completed: null, status: "queued", cookie: cookies[i % cookies.length] });
      })
      .catch(() => { submitFailures++; });
    if (RATE > 0) await sleep(1000 / RATE);
  }

  // Let the submissions land before polling.
  await sleep(1500);
  console.log(`Submitted ${scans.size}/${COUNT}${submitFailures ? ` (${submitFailures} rejected)` : ""}\n`);
  if (scans.size === 0) { console.error("Nothing was accepted — aborting."); process.exit(1); }

  // ── Poll to completion, sampling concurrency and memory ──────────────────
  const samples = []; // { t, running, done, rssMb }
  let lastLog = 0;

  for (let tick = 0; tick < 3600; tick++) {
    const ids = [...scans.keys()];
    const results = await Promise.all(
      ids.map((id) =>
        fetch(`${BASE}/api/scans/${id}`, { headers: { Cookie: scans.get(id).cookie } })
          .then((r) => (r.ok ? r.json() : null))
          .catch(() => null),
      ),
    );

    let running = 0;
    let done = 0;
    for (let i = 0; i < ids.length; i++) {
      const rec = scans.get(ids[i]);
      const s = results[i]?.scan ?? results[i];
      if (!s) continue;
      if (rec.started === null && s.status !== "queued") rec.started = Date.now();
      if (rec.completed === null && (s.status === "complete" || s.status === "failed")) {
        rec.completed = Date.now();
        rec.status = s.status;
      }
      if (rec.completed !== null) done++;
      else if (rec.started !== null) running++;
    }

    let rssMb = null;
    try {
      const h = await fetch(`${BASE}/api/system/health`).then((r) => r.json());
      rssMb = h?.memory?.rssMb ?? null;
    } catch { /* health may not expose memory */ }

    samples.push({ t: Date.now() - t0, running, done, rssMb });

    const elapsed = Date.now() - t0;
    if (elapsed - lastLog > 10000) {
      lastLog = elapsed;
      console.log(`  ${pad(fmt(elapsed), 8)} running=${pad(running, 4)} done=${pad(done, 5)}${rssMb ? ` rss=${rssMb}MB` : ""}`);
    }
    if (done === scans.size) break;
    await sleep(500);
  }

  // ── Report ────────────────────────────────────────────────────────────────
  const recs = [...scans.values()];
  const finished = recs.filter((r) => r.completed !== null);
  const failed = finished.filter((r) => r.status === "failed").length;
  const waits = finished.filter((r) => r.started).map((r) => r.started - r.submitted).sort((a, b) => a - b);
  const execs = finished.filter((r) => r.started).map((r) => r.completed - r.started).sort((a, b) => a - b);
  const totals = finished.map((r) => r.completed - r.submitted).sort((a, b) => a - b);
  const wall = Date.now() - t0;
  const peakConc = Math.max(...samples.map((s) => s.running), 0);
  const peakRss = Math.max(...samples.map((s) => s.rssMb ?? 0), 0);

  console.log("\n" + "=".repeat(62));
  console.log(`Completed ${finished.length}/${scans.size} in ${fmt(wall)}${failed ? `  (${failed} failed)` : ""}`);
  console.log("=".repeat(62));
  console.log(`  throughput          ${(finished.length / (wall / 60000)).toFixed(1)} scans/min`);
  console.log(`  peak concurrency    ${peakConc}   <- the cap actually reached`);
  if (peakRss) console.log(`  peak RSS            ${peakRss} MB`);
  console.log("");
  console.log(`  ${pad("", 20)}${pad("p50", 9)}${pad("p90", 9)}${pad("p99", 9)}max`);
  console.log(`  ${pad("queue wait", 20)}${pad(fmt(pct(waits, 50)), 9)}${pad(fmt(pct(waits, 90)), 9)}${pad(fmt(pct(waits, 99)), 9)}${fmt(waits.at(-1) ?? 0)}`);
  console.log(`  ${pad("execution", 20)}${pad(fmt(pct(execs, 50)), 9)}${pad(fmt(pct(execs, 90)), 9)}${pad(fmt(pct(execs, 99)), 9)}${fmt(execs.at(-1) ?? 0)}`);
  console.log(`  ${pad("total (felt)", 20)}${pad(fmt(pct(totals, 50)), 9)}${pad(fmt(pct(totals, 90)), 9)}${pad(fmt(pct(totals, 99)), 9)}${fmt(totals.at(-1) ?? 0)}`);
  console.log("");

  // The diagnosis the numbers support, stated rather than left to the reader.
  const medWait = pct(waits, 50);
  const medExec = pct(execs, 50);
  if (medWait > medExec * 2) {
    console.log(`  BOTTLENECK: queueing. Median wait ${fmt(medWait)} vs execution ${fmt(medExec)} —`);
    console.log(`  scans are fast but there are not enough slots. Raise concurrency or replicas.`);
  } else if (medExec > 60000) {
    console.log(`  BOTTLENECK: scan execution (${fmt(medExec)} median). More slots will not help;`);
    console.log(`  the work itself is slow. Profile the scan, not the queue.`);
  } else {
    console.log(`  No queueing bottleneck: median wait ${fmt(medWait)} against ${fmt(medExec)} execution.`);
    console.log(`  Capacity is keeping up with this arrival rate.`);
  }
  if (peakConc > 0 && peakConc < 3) {
    console.log(`  NOTE: peak concurrency only reached ${peakConc}. Either the burst was too small`);
    console.log(`  to saturate, or something is serialising the work.`);
  }
  console.log("");

  if (failed) process.exit(1);
}

main().catch((err) => { console.error(err); process.exit(2); });
