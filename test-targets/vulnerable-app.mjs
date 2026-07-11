// INTENTIONALLY VULNERABLE test target — for exercising Seclayer's active
// red-team probes against a local app you own. NOT for production. It only
// *simulates* vulnerable responses (it never actually runs SQL or shells out) so
// it is safe to run, while still tripping each probe signature the scanner looks
// for. The ONE real side effect is a deliberate blind-SSRF: it fetches an
// attacker-supplied http(s) URL server-side so the out-of-band collaborator probe
// has something to catch (see the `url` handler below).
//
//   node test-targets/vulnerable-app.mjs [port]
//
// Then point Seclayer at http://127.0.0.1:<port> with SCAN_DEV_ALLOW_HOSTS set.
import http from 'node:http';

const PORT = Number(process.argv[2] || process.env.VULN_PORT || 4100);

// Two seeded tenants for the BOLA/IDOR demo. /api/orders/:id returns ANY order to
// ANY authenticated token (no ownership check) and 401 when unauthenticated — so a
// two-identity scan can prove tenant-A reading tenant-B's order.
const ORDERS = {
  '1001': { id: '1001', owner: 'tok-alice', email: 'alice@vulnshop.test', total: '$42.00', card: '**** 4242' },
  '1002': { id: '1002', owner: 'tok-bob', email: 'bob@vulnshop.test', total: '$88.00', card: '**** 1881' },
};

const server = http.createServer((req, res) => {
  const u = new URL(req.url, `http://127.0.0.1:${PORT}`);
  const q = u.searchParams;

  // 5. BOLA / IDOR — object-level authorization is missing: any valid token can
  //    read any order id.
  const om = u.pathname.match(/^\/api\/orders\/(\d+)$/);
  if (om) {
    const tok = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
    if (!tok) { res.writeHead(401, { 'Content-Type': 'application/json' }); res.end('{"error":"unauthorized"}'); return; }
    const o = ORDERS[om[1]];
    if (!o) { res.writeHead(404, { 'Content-Type': 'application/json' }); res.end('{"error":"not found"}'); return; }
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); return;
  }

  let body = `<!doctype html><html><head><title>Vulnerable Test App</title></head>`
    + `<body><h1>Intentionally Vulnerable Test Target</h1>`
    + `<p>For local Seclayer red-team probe testing only.</p>`;

  // 1. SQL injection — reflect a database error signature when `id` is present.
  if (q.has('id')) {
    body += `<div class="err">Database error: You have an error in your SQL syntax; `
      + `check the manual that corresponds to your MySQL server version near `
      + `'${q.get('id')}' at line 1</div>`;
  }
  // 2. Reflected XSS — echo `q` back completely unescaped.
  if (q.has('q')) {
    body += `<div class="results">Search results for: ${q.get('q')}</div>`;
  }
  // 3. OS command injection — simulate a shell that evaluates the injected
  //    command. `expr A + B` returns the computed sum (arithmetic oracle), and
  //    `id` returns a uid/gid line. Nothing is actually executed — the responses
  //    are computed/hardcoded so the target stays safe to run.
  if (q.has('ping')) {
    const ping = q.get('ping');
    let out = `PING ${ping}`;
    const expr = /expr\s+(\d+)\s*\+\s*(\d+)/.exec(ping);
    if (expr) out += `\n${Number(expr[1]) + Number(expr[2])}`;
    if (/;\s*id\b/.test(ping)) out += `\nuid=0(root) gid=0(root) groups=0(root)`;
    body += `<pre>${out}</pre>`;
  }
  // 4. SSRF — pretend to have fetched the attacker-supplied URL and leak a banner
  //    (reflected case). For a real http(s) URL that ISN'T the simulated
  //    loopback:22 banner, actually fetch it server-side (fire-and-forget) so the
  //    out-of-band collaborator probe records a genuine blind-SSRF callback.
  if (q.has('url')) {
    const target = q.get('url');
    if (/^https?:\/\//i.test(target) && !/127\.0\.0\.1:22/.test(target)) {
      fetch(target).catch(() => {});
    }
    body += `<pre>Response from ${target}:\nSSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1</pre>`;
  }

  body += `</body></html>`;

  // Deliberately omit every security header (CSP/HSTS/X-Frame-Options/etc.) so
  // the passive IAST checks also flag this target.
  res.writeHead(200, { 'Content-Type': 'text/html', 'Server': 'VulnTestApp/1.0' });
  res.end(body);
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[vuln-app] intentionally-vulnerable target listening on http://127.0.0.1:${PORT}`);
});
