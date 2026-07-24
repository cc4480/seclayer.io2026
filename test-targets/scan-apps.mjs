// Batch detection-coverage harness. Scans a list of YOUR OWN target apps with the
// full aggressive sweep and reports, per app, which vulnerability classes the
// scanner detected — and, when you declare the vuln each app is meant to have,
// whether the scanner caught it (PASS/FAIL). Built for validating detection across
// many intentionally-vulnerable apps you published for this purpose.
//
// Usage:
//   1. Make sure the dev server is running (npm run dev) with DEV_SKIP_DOMAIN_
//      VERIFICATION=true so active/aggressive probes run without the ownership step.
//   2. Create test-targets/apps.json (see apps.example.json). Each entry:
//        { "url": "https://your-app.example.com",
//          "expect": ["SQL Injection"],           // optional: class name substrings
//          "authHeader": "Bearer <token>",         // optional: reach auth-gated surface
//          "bola": [ {identityA}, {identityB} ] }  // optional: two-identity BOLA
//      A bare string "https://app" is also accepted (no expectations).
//   3. node test-targets/scan-apps.mjs
//
// Env: SECLAYER_BASE (default http://localhost:3000), CONCURRENCY (default 4),
//      APPS_FILE (default test-targets/apps.json), SCAN_TIMEOUT_MS (default 600000).

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const BASE = process.env.SECLAYER_BASE || 'http://localhost:3000';
const CONCURRENCY = Number(process.env.CONCURRENCY || 4);
const APPS_FILE = process.env.APPS_FILE || join(HERE, 'apps.json');
const SCAN_TIMEOUT_MS = Number(process.env.SCAN_TIMEOUT_MS || 600000);

// Canonical vuln classes → the finding-title substrings that indicate detection.
// Column order is the matrix order.
const CLASSES = [
  ['SQLi',    ['SQL Injection']],
  ['XSS',     ['Reflected XSS', 'Cross-Site Scripting']],
  ['CmdInj',  ['Command Injection']],
  ['SSRF',    ['Server-Side Request Forgery (SSRF)']],
  ['bSSRF',   ['Blind Server-Side Request Forgery']],
  ['SSTI',    ['Template Injection']],
  ['LFI',     ['Path Traversal', 'Local File Inclusion']],
  ['OpenRdr', ['Open Redirect']],
  ['CRLF',    ['CRLF', 'Response Header Injection']],
  ['CORS',    ['CORS Misconfiguration']],
  ['XXE',     ['XML External Entity']],
  ['NoSQL',   ['NoSQL']],
  ['GraphQL', ['GraphQL']],
  ['BOLA',    ['Broken Object Level Authorization']],
  ['ExpObj',  ['Exposed User Object', 'Unauthenticated User Object', 'Unauthenticated Access to Protected']],
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const hasTitle = (findings, needle) => findings.some((f) => (f.title || '').includes(needle));

function loadApps() {
  if (!existsSync(APPS_FILE)) {
    console.error(`\nNo targets file at ${APPS_FILE}.\nCreate it (copy test-targets/apps.example.json) with your app URLs, then re-run.\n`);
    process.exit(2);
  }
  let raw;
  try { raw = JSON.parse(readFileSync(APPS_FILE, 'utf8')); }
  catch (e) { console.error(`Could not parse ${APPS_FILE}: ${e.message}`); process.exit(2); }
  if (!Array.isArray(raw) || raw.length === 0) { console.error(`${APPS_FILE} must be a non-empty JSON array.`); process.exit(2); }
  return raw.map((e) => (typeof e === 'string' ? { url: e } : e)).filter((e) => e && e.url);
}

async function scanOne(app) {
  const body = {
    url: app.url,
    activeProbes: true,
    aggressiveProbes: true,
    ...(app.authHeader ? { authHeader: app.authHeader } : {}),
    ...(Array.isArray(app.bola) && app.bola.length === 2 ? { bolaIdentities: app.bola } : {}),
  };
  let launch;
  try {
    launch = await fetch(`${BASE}/api/scans`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  } catch (e) {
    return { app, error: `launch failed: ${e.message}` };
  }
  if (!launch.ok) return { app, error: `launch HTTP ${launch.status}: ${(await launch.text()).slice(0, 200)}` };
  const scanId = (await launch.json()).scan?.id;
  if (!scanId) return { app, error: 'no scan id returned' };

  const deadline = Date.now() + SCAN_TIMEOUT_MS;
  while (Date.now() < deadline) {
    await sleep(3000);
    let s;
    try { const r = await fetch(`${BASE}/api/scans/${scanId}`); if (!r.ok) continue; s = (await r.json()).scan; }
    catch { continue; }
    if (s.status === 'complete' || s.status === 'failed') {
      if (s.status === 'failed') return { app, scanId, error: `scan failed: ${s.error || 'unknown'}` };
      return { app, scanId, scan: s };
    }
  }
  return { app, scanId, error: 'timed out waiting for completion' };
}

// Simple concurrency pool.
async function pool(items, size, worker) {
  const out = new Array(items.length);
  let i = 0;
  const run = async () => { while (i < items.length) { const idx = i++; out[idx] = await worker(items[idx], idx); } };
  await Promise.all(Array.from({ length: Math.min(size, items.length) }, run));
  return out;
}

function pad(s, n) { s = String(s); return s.length >= n ? s.slice(0, n) : s + ' '.repeat(n - s.length); }

async function main() {
  const apps = loadApps();
  console.log(`\nScanning ${apps.length} app(s) via ${BASE}  (concurrency ${CONCURRENCY}, full aggressive sweep)\n`);

  let done = 0;
  const results = await pool(apps, CONCURRENCY, async (app) => {
    const r = await scanOne(app);
    done++;
    const tag = r.error ? `ERROR (${r.error})` : `${r.scan.findings?.length ?? 0} findings, score ${r.scan.score}`;
    console.log(`  [${done}/${apps.length}] ${app.url} → ${tag}`);
    return r;
  });

  // ---- Coverage matrix ----
  const header = 'TARGET'.padEnd(42) + CLASSES.map(([c]) => pad(c, 8)).join('') + 'EXPECTED';
  const lines = [header, '-'.repeat(header.length)];
  let expectTotal = 0, expectCaught = 0, errored = 0;

  for (const r of results) {
    const urlCol = pad(r.app.url, 40) + '  ';
    if (r.error) { lines.push(urlCol + pad('— scan error —', CLASSES.length * 8) + r.error); errored++; continue; }
    const findings = r.scan.findings || [];
    const cells = CLASSES.map(([, needles]) => pad(needles.some((n) => hasTitle(findings, n)) ? 'yes' : '·', 8)).join('');
    let expectCol = '';
    if (Array.isArray(r.app.expect) && r.app.expect.length) {
      const missed = r.app.expect.filter((needle) => !hasTitle(findings, needle));
      expectTotal++;
      if (missed.length === 0) { expectCaught++; expectCol = 'PASS'; }
      else expectCol = `MISS: ${missed.join(', ')}`;
    } else {
      expectCol = '(no expectation set)';
    }
    lines.push(urlCol + cells + expectCol);
  }

  const legend = 'Legend: ' + CLASSES.map(([c]) => c).join(' ');
  const summary = [
    '',
    `Apps scanned: ${results.length}   errors: ${errored}`,
    (expectTotal ? `Expected-vuln detection: ${expectCaught}/${expectTotal} apps caught their declared vuln` : 'No per-app expectations set — showing detected classes only.'),
  ].join('\n');

  const report = ['# Seclayer detection-coverage report', '', '```', ...lines, '```', '', legend, summary].join('\n');
  console.log('\n' + lines.join('\n') + '\n\n' + legend + summary + '\n');

  const mdPath = join(HERE, 'coverage-report.md');
  const jsonPath = join(HERE, 'coverage-report.json');
  writeFileSync(mdPath, report);
  writeFileSync(jsonPath, JSON.stringify(results.map((r) => ({
    url: r.app.url, error: r.error || null, scanId: r.scanId || null,
    score: r.scan?.score ?? null, findings: (r.scan?.findings || []).map((f) => ({ title: f.title, severity: f.severity, category: f.category })),
  })), null, 2));
  console.log(`Full report written to:\n  ${mdPath}\n  ${jsonPath}\n`);

  // Non-zero exit if any declared expectation was missed or any app errored.
  process.exit((expectTotal && expectCaught !== expectTotal) || errored ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(2); });
