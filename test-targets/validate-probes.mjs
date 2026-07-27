// Probe validation harness. Scans the bundled intentionally-vulnerable app and
// asserts that EVERY active red-team / API probe fired and produced its expected
// finding — a repeatable "are the probes still working?" check. Prints a
// pass/fail matrix and exits non-zero if any expected probe is missing.
//
// Prereqs (all local, dev only):
//   1. Seclayer dev server running with, in .env.local:
//        DEV_SKIP_DOMAIN_VERIFICATION="true"   (unlock active probes, no ownership proof)
//        SCAN_DEV_ALLOW_HOSTS="127.0.0.1:4100" (let the SSRF guard reach the target)
//        OOB_BASE_URL="http://127.0.0.1:3000"  (collaborator for the blind-SSRF probe)
//   2. The vulnerable target running:  node test-targets/vulnerable-app.mjs 4100
//
// Then:  node test-targets/validate-probes.mjs
//
// Override endpoints via env: SECLAYER_BASE (default http://localhost:3000),
// TARGET_URL (default http://127.0.0.1:4100).

const BASE = process.env.SECLAYER_BASE || 'http://localhost:3000';
const TARGET = process.env.TARGET_URL || 'http://127.0.0.1:4100';

// The vulnerable app seeds two tenants for the two-identity BOLA proof.
const bolaIdentities = [
  { label: 'tenant-A', authHeader: 'Bearer tok-alice', ownResource: '/api/orders/1001', ownMarker: 'alice@vulnshop.test' },
  { label: 'tenant-B', authHeader: 'Bearer tok-bob', ownResource: '/api/orders/1002', ownMarker: 'bob@vulnshop.test' },
];

// Each probe we expect to fire against the reference target, matched by a
// substring of the finding title (titles are authored in the probe modules).
const EXPECTED = [
  // Red-team tier
  { probe: 'SQL Injection (error-signature)',        titleIncludes: 'SQL Injection' },
  { probe: 'Reflected XSS (execution-gated)',        titleIncludes: 'Reflected XSS' },
  { probe: 'OS Command Injection (arith oracle)',    titleIncludes: 'Command Injection' },
  { probe: 'Reflected SSRF (SSH banner)',            titleIncludes: 'Server-Side Request Forgery (SSRF)' },
  { probe: 'Blind SSRF (out-of-band callback)',      titleIncludes: 'Blind Server-Side Request Forgery' },
  { probe: 'GraphQL Introspection',                  titleIncludes: 'GraphQL Schema Introspection' },
  { probe: 'Exposed User Object Endpoint',           titleIncludes: 'Exposed User Object' },
  { probe: 'BOLA / cross-tenant read',               titleIncludes: 'Broken Object Level Authorization' },
  // Aggressive tier
  { probe: 'SSTI (arithmetic oracle)',               titleIncludes: 'Server-Side Template Injection' },
  { probe: 'Path Traversal / LFI',                   titleIncludes: 'Path Traversal' },
  { probe: 'Open Redirect',                          titleIncludes: 'Open Redirect' },
  { probe: 'CRLF / header injection',                titleIncludes: 'CRLF' },
  { probe: 'CORS misconfiguration',                  titleIncludes: 'CORS Misconfiguration' },
  { probe: 'XXE (out-of-band)',                      titleIncludes: 'XML External Entity' },
  { probe: 'NoSQL injection (operator bypass)',      titleIncludes: 'NoSQL Injection' },
];

// Discovered-parameter fuzzing checks — only asserted when the target is started
// with VULN_EXPOSE_SURFACE=1 (which exposes crawlable parameterized links). The
// default target has NO discoverable surface, so a plain scan stays clean.
if (process.env.VULN_EXPOSE_SURFACE === '1') {
  EXPECTED.push(
    { probe: 'SQLi — discovered param',              titleIncludes: 'SQL Injection (discovered parameter' },
    { probe: 'XSS — discovered param',               titleIncludes: 'Reflected XSS (discovered parameter' },
    { probe: 'SSTI — discovered param',              titleIncludes: 'Template Injection (discovered parameter' },
    { probe: 'LFI — discovered param',               titleIncludes: 'Local File Inclusion (discovered parameter' },
    { probe: 'Open Redirect — discovered param',     titleIncludes: 'Open Redirect (discovered parameter' },
    { probe: 'CRLF — discovered param',              titleIncludes: 'Header Injection (discovered parameter' },
    // POST-body fuzzing: the crawler discovers a <form method=POST action=/submit-review>
    // and the fuzzer confirms injection in its form FIELDS (not just GET query
    // params). Matched on the form's endpoint path so these are unambiguously the
    // POST-body findings, distinct from the GET-link rows above.
    { probe: 'XSS — discovered POST form field',     titleIncludes: 'Reflected XSS (discovered parameter "q" on /submit-review' },
    { probe: 'SQLi — discovered POST form field',    titleIncludes: 'SQL Injection (discovered parameter "id" on /submit-review' },
    // Stored/persistent XSS: submit a marker to the /guestbook form, then see it
    // served back unescaped on a separate GET.
    { probe: 'Stored XSS — discovered form',         titleIncludes: 'Stored XSS (discovered form field "comment" on /guestbook' },
  );
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  console.log(`\nProbe validation → target ${TARGET} via ${BASE}\n`);

  // 1. Launch an active scan with the two BOLA identities.
  const launch = await fetch(`${BASE}/api/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: TARGET, activeProbes: true, aggressiveProbes: true, bolaIdentities }),
  });
  if (!launch.ok) {
    console.error(`Failed to launch scan: HTTP ${launch.status} ${await launch.text()}`);
    process.exit(2);
  }
  const { scan } = await launch.json();
  console.log(`Launched scan ${scan.id} (status: ${scan.status}) — waiting for completion…`);

  // 2. Poll to completion (active probes + OOB wait can take ~2-4 min).
  let final = null;
  for (let i = 0; i < 180; i++) {
    await sleep(2000);
    const res = await fetch(`${BASE}/api/scans/${scan.id}`);
    if (!res.ok) continue;
    const body = await res.json();
    const s = body.scan || body;
    if (i > 0 && i % 15 === 0) console.log(`  …still ${s.status} (${i * 2}s elapsed)`);
    if (s.status === 'complete' || s.status === 'failed') { final = s; break; }
  }
  if (!final) { console.error('Scan did not finish within the timeout.'); process.exit(2); }
  if (final.status === 'failed') { console.error(`Scan failed: ${final.error || 'unknown error'}`); process.exit(2); }

  const findings = final.findings || [];
  console.log(`\nScan complete — status=${final.status}, score=${final.score}/100, activeProbesRun=${final.evidence?.activeProbesRun}`);
  console.log(`Total findings: ${findings.length}\n`);

  // 3. Evaluate each expected probe.
  const titles = findings.map((f) => f.title || '');
  let passed = 0;
  const rows = EXPECTED.map(({ probe, titleIncludes }) => {
    const hit = findings.find((f) => (f.title || '').includes(titleIncludes));
    if (hit) passed++;
    return { probe, ok: !!hit, detail: hit ? `[${(hit.severity || '').toUpperCase()}] ${hit.title}` : 'NOT DETECTED' };
  });

  const pad = (s, n) => (s + ' '.repeat(n)).slice(0, n);
  console.log(pad('PROBE', 36) + pad('RESULT', 8) + 'FINDING');
  console.log('-'.repeat(90));
  for (const r of rows) {
    console.log(pad(r.probe, 36) + pad(r.ok ? 'PASS' : 'FAIL', 8) + r.detail);
  }
  console.log('-'.repeat(90));
  console.log(`\n${passed}/${EXPECTED.length} probes fired.\n`);

  if (passed !== EXPECTED.length) {
    console.log('All findings seen this run:');
    for (const t of titles) console.log(`  - ${t}`);
    console.log('');
    process.exit(1);
  }
  console.log('All probes working ✔');
}

main().catch((err) => { console.error(err); process.exit(2); });
