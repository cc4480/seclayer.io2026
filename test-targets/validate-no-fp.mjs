// False-positive validation harness — the mirror of validate-probes.mjs.
//
// validate-probes points the active probes at vulnerable-app.mjs and asserts
// every one FIRED. This points them at hardened-app.mjs and asserts every one
// STAYED SILENT. Neither run is worth much alone: the first proves the scanner
// can see, the second proves it is not hallucinating, and an accuracy claim
// needs both.
//
// The target is not merely safe, it is BAIT — it serves the /etc/passwd line,
// the SSH banner, the `id` output, powers of seven, a Postgres syntax error and
// a set of placeholder credentials as STATIC page content, alongside every
// parameter its vulnerable twin is exploited through. So a finding here is
// specifically the scanner reading the presence of a signature as the meaning of
// a response — the error the false-positive audit has recorded most often.
//
// Prereqs (all local, dev only):
//   1. Seclayer dev server running with, in .env.local:
//        DEV_SKIP_DOMAIN_VERIFICATION="true"   (unlock active probes)
//        SCAN_DEV_ALLOW_HOSTS="127.0.0.1:4101" (let the SSRF guard reach it)
//        OOB_BASE_URL="http://127.0.0.1:3000"  (so blind SSRF/XXE could call back)
//   2. The hardened target running:  node test-targets/hardened-app.mjs 4101
//
// Then:  node test-targets/validate-no-fp.mjs
//
// Exit 0 = zero actionable findings. Exit 1 = at least one false positive, each
// printed with its evidence so it can be checked by hand before anyone "fixes"
// a working check.
//
// Override via env: SECLAYER_BASE (default http://localhost:3000),
// TARGET_URL (default http://127.0.0.1:4101).

const BASE = process.env.SECLAYER_BASE || 'http://localhost:3000';
const TARGET = process.env.TARGET_URL || 'http://127.0.0.1:4101';

// /api/scans needs a session. A dev server with DEV_SKIP_AUTH on supplies one
// automatically, but this harness should also work against a production-shaped
// instance, so it can sign itself in: with no email provider configured the
// request-code endpoint returns the code in its response (dev/demo only), which
// is enough to complete the real two-step sign-in and get a session cookie.
// Pass SECLAYER_COOKIE to skip this and use a session you already have.
const HARNESS_EMAIL = process.env.HARNESS_EMAIL || 'fp-harness@seclayer.test';

async function signIn() {
  if (process.env.SECLAYER_COOKIE) return process.env.SECLAYER_COOKIE;

  const req = await fetch(`${BASE}/api/auth/request-code`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: HARNESS_EMAIL }),
  });
  const body = await req.json().catch(() => ({}));
  if (!req.ok) throw new Error(`request-code failed: HTTP ${req.status} ${JSON.stringify(body)}`);
  if (!body.devCode) {
    throw new Error(
      'request-code did not return a devCode, so this harness cannot sign itself in. ' +
      'Either run the instance without an email provider (ALLOW_MISSING_EMAIL_PROVIDER=true), ' +
      'or pass SECLAYER_COOKIE with an existing session.',
    );
  }

  const verify = await fetch(`${BASE}/api/auth/verify-code`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: HARNESS_EMAIL, code: body.devCode }),
  });
  if (!verify.ok) throw new Error(`verify-code failed: HTTP ${verify.status} ${await verify.text()}`);

  const setCookie = verify.headers.getSetCookie?.() ?? [];
  const cookie = setCookie.map((c) => c.split(';')[0]).join('; ');
  if (!cookie) throw new Error('verify-code returned no session cookie');
  return cookie;
}

// The same two identities validate-probes uses, so the BOLA differential runs
// with a real second account. On this target A must NOT be able to read B's
// order — a cross-tenant finding here is a false positive.
const bolaIdentities = [
  { label: 'tenant-A', authHeader: 'Bearer tok-alice', ownResource: '/api/orders/1001', ownMarker: '1001' },
  { label: 'tenant-B', authHeader: 'Bearer tok-bob', ownResource: '/api/orders/1002', ownMarker: '1002' },
];

// Informational rows are scan-coverage context, not detections — they are not
// false positives and are excluded from the verdict. Everything at low or above
// counts. The severity names match server/scanTypes.ts.
const ACTIONABLE = new Set(['critical', 'high', 'medium', 'low']);

// Findings that are TRUE of this target and therefore must not count against
// it. Keep this list tiny and justified — every entry is a claim that the
// finding is correct, not an excuse to silence one.
const EXPECTED_TRUE = [
  {
    // The target is plain HTTP on loopback by design (it exists to be scanned
    // locally), so anything keyed on "not HTTPS" is correct about it.
    match: (f) => /insecure connection|https|tls|ssl|certificate|insecure transport/i.test(f.title || ''),
    why: 'the target is intentionally plain HTTP on 127.0.0.1',
  },
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const pad = (s, n) => (String(s) + ' '.repeat(n)).slice(0, n);

async function main() {
  console.log(`\nFalse-positive validation → target ${TARGET} via ${BASE}`);
  console.log('Correct result: ZERO actionable findings.\n');

  const cookie = await signIn();

  const launch = await fetch(`${BASE}/api/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: cookie },
    body: JSON.stringify({ url: TARGET, activeProbes: true, aggressiveProbes: true, bolaIdentities }),
  });
  if (!launch.ok) {
    console.error(`Failed to launch scan: HTTP ${launch.status} ${await launch.text()}`);
    process.exit(2);
  }
  const { scan } = await launch.json();
  console.log(`Launched scan ${scan.id} — waiting for completion…`);

  let final = null;
  for (let i = 0; i < 180; i++) {
    await sleep(2000);
    const res = await fetch(`${BASE}/api/scans/${scan.id}`, { headers: { Cookie: cookie } });
    if (!res.ok) continue;
    const body = await res.json();
    const s = body.scan || body;
    if (i > 0 && i % 15 === 0) console.log(`  …still ${s.status} (${i * 2}s elapsed)`);
    if (s.status === 'complete' || s.status === 'failed') { final = s; break; }
  }
  if (!final) { console.error('Scan did not finish within the timeout.'); process.exit(2); }
  if (final.status === 'failed') { console.error(`Scan failed: ${final.error || 'unknown'}`); process.exit(2); }

  const findings = final.findings || [];
  console.log(`\nScan complete — score=${final.score}/100, activeProbesRun=${final.evidence?.activeProbesRun}`);
  console.log(`Total findings: ${findings.length} (informational rows do not count)\n`);

  const actionable = findings.filter((f) => ACTIONABLE.has(String(f.severity || '').toLowerCase()));

  const accepted = [];
  const falsePositives = [];
  for (const f of actionable) {
    const rule = EXPECTED_TRUE.find((r) => r.match(f));
    if (rule) accepted.push({ f, why: rule.why });
    else falsePositives.push(f);
  }

  if (accepted.length) {
    console.log('Accepted as TRUE of this target:');
    for (const { f, why } of accepted) {
      console.log(`  · [${String(f.severity).toUpperCase()}] ${f.title}  — ${why}`);
    }
    console.log('');
  }

  // A scan that produced no actionable findings AND ran no active probes has
  // proved nothing — it would pass just as happily against an unreachable host.
  // Fail loudly instead of reporting a clean sweep that never swept.
  // activeProbesRun is a BOOLEAN (did the active tier run at all), not a count.
  const probesRun = final.evidence?.activeProbesRun === true;
  if (!probesRun) {
    console.error('No active probes ran — this run proves nothing.');
    console.error('Check DEV_SKIP_DOMAIN_VERIFICATION and SCAN_DEV_ALLOW_HOSTS, and that the target is up.');
    process.exit(2);
  }

  if (falsePositives.length === 0) {
    console.log('Zero false positives, with the active probe tier confirmed to have run ✔');
    console.log(`(${findings.length - actionable.length} informational rows, ${accepted.length} accepted as true)\n`);
    return;
  }

  console.log(pad('SEVERITY', 11) + pad('CONF', 6) + 'FALSE POSITIVE');
  console.log('-'.repeat(96));
  for (const f of falsePositives) {
    console.log(pad(String(f.severity).toUpperCase(), 11) + pad(f.confidence ?? '', 6) + (f.title || ''));
    const ev = f.evidence?.signal?.quote || f.evidence?.demonstration || f.howVerified || '';
    if (ev) console.log(`${' '.repeat(17)}${String(ev).slice(0, 150)}`);
  }
  console.log('-'.repeat(96));
  console.log(`\n${falsePositives.length} false positive(s) on a target that has none of these flaws.`);
  console.log('Check each against the live response BEFORE changing a check — see');
  console.log('the false-positive audit: a correct check has been deleted this way before.\n');
  process.exit(1);
}

main().catch((err) => { console.error(err); process.exit(2); });
