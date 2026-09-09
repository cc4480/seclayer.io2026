// Live false-positive sanity runner.
//
// Runs the PASSIVE scan pipeline (headers, TLS, secrets, libraries, DNS/subdomain
// recon, sensitive-path probing — NO active exploit probes) against one or more
// real sites and prints the findings so you can eyeball them for false positives.
// Point it at well-secured sites you trust (github.com, cloudflare.com,
// mozilla.org, …): a good scan should return few findings and ZERO false ones.
//
// Usage:
//   node --import tsx scripts/live-scan.ts https://github.com https://www.cloudflare.com
//   node --import tsx scripts/live-scan.ts            # uses the default reputable list
//
// Requires open outbound HTTPS egress. Active exploit probing is intentionally
// NOT run here — it's gated behind domain-ownership verification in the product,
// and you must never aim it at sites you don't own. This runner is passive only.
//
// If your environment routes outbound traffic through a proxy, set HTTPS_PROXY
// (and NODE_EXTRA_CA_CERTS to the proxy CA) before running; the script installs
// an undici ProxyAgent when HTTPS_PROXY is present.
import { runDiagnostics } from '../server/scanner.js';
import { compileStaticFindings } from '../server/findings.js';

const DEFAULT_TARGETS = [
  'https://github.com',
  'https://www.cloudflare.com',
  'https://www.mozilla.org',
  'https://developer.mozilla.org',
  'https://en.wikipedia.org',
];

async function maybeInstallProxy(): Promise<void> {
  const proxy = process.env.HTTPS_PROXY || process.env.https_proxy;
  if (!proxy) return;
  try {
    const undici = await import('undici');
    undici.setGlobalDispatcher(new undici.ProxyAgent(proxy));
    console.log(`[live-scan] Routing through HTTPS_PROXY=${proxy}\n`);
  } catch {
    console.warn('[live-scan] HTTPS_PROXY set but undici ProxyAgent could not be installed; continuing direct.\n');
  }
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;

async function scanOne(url: string): Promise<{ url: string; score: number; nonInfo: number; findings: any[]; diag?: any } | null> {
  try {
    const started = Date.now();
    const diag = await runDiagnostics(url, undefined, { allowActiveProbes: false });
    const { score, findings } = compileStaticFindings(diag);
    const sorted = [...findings].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
    return {
      url,
      score,
      nonInfo: findings.filter((f) => f.severity !== 'info').length,
      findings: sorted,
      diag: {
        finalUrl: diag.url,
        responseStatus: diag.responseStatus,
        elapsedMs: Date.now() - started,
      },
    };
  } catch (err: any) {
    console.log(`\n=== ${url} ===\n  ERROR: ${err?.message || err}`);
    return { url, score: 0, nonInfo: 0, findings: [], diag: { failed: String(err?.message || err) } } as any;
  }
}

async function main() {
  await maybeInstallProxy();
  const argv = process.argv.slice(2);
  // `--json <path>` also writes the full result per target, so a run can be
  // aggregated and verified rather than only eyeballed. Passive output unchanged.
  const ji = argv.indexOf('--json');
  const jsonDest = ji !== -1 ? argv[ji + 1] : null;
  if (jsonDest && !jsonDest.trim()) throw new Error('--json needs a destination path');
  const targets = argv.filter((a, i) => a !== '--json' && argv[i - 1] !== '--json');
  const list = targets.length ? targets : DEFAULT_TARGETS;
  console.log(`[live-scan] Passive scan of ${list.length} target(s). Review non-info findings for false positives.\n`);

  const results = [];
  const collected: any[] = [];
  for (const url of list) {
    const r = await scanOne(url);
    if (!r) continue;
    collected.push({
      url,
      ...(r.diag ?? {}),
      score: r.score,
      findings: r.findings.map((f: any) => ({
        title: f.title,
        severity: f.severity,
        category: f.category,
        owasp: f.owasp ?? null,
        confidence: f.confidence ?? null,
        endpoint: f.endpoint ?? null,
        verification: f.verification ?? null,
        description: f.description ? String(f.description).slice(0, 600) : null,
      })),
    });
    if (r.diag?.failed) continue;
    results.push(r);
    console.log(`\n=== ${r.url} ===  score ${r.score}/100  ·  ${r.nonInfo} actionable finding(s)`);
    for (const f of r.findings) {
      console.log(`  [${f.severity.toUpperCase()}] ${f.title}`);
      if (f.verification) console.log(`      how verified: ${f.verification}`);
    }
  }

  if (jsonDest) {
    const { writeFileSync } = await import('node:fs');
    writeFileSync(jsonDest, JSON.stringify({ scannedAt: new Date().toISOString(), results: collected }, null, 1));
    console.log(`\n[live-scan] Wrote ${jsonDest} — ${collected.length} result(s).`);
  }

  console.log('\n----------------------------------------');
  console.log('SUMMARY (scrutinize any actionable finding on a site you trust — that is your FP signal):');
  for (const r of results) {
    console.log(`  ${r.url.padEnd(38)} score ${String(r.score).padStart(3)}  ·  ${r.nonInfo} actionable`);
  }
}

main().catch((e) => { console.error('[live-scan] fatal:', e); process.exit(1); });
