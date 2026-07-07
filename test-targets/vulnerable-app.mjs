// INTENTIONALLY VULNERABLE test target — for exercising Seclayer's active
// red-team probes against a local app you own. NOT for production. It only
// *simulates* vulnerable responses (it never actually runs SQL, shells out, or
// makes outbound requests) so it is safe to run, while still tripping each probe
// signature the scanner looks for.
//
//   node test-targets/vulnerable-app.mjs [port]
//
// Then point Seclayer at http://127.0.0.1:<port> with SCAN_DEV_ALLOW_HOSTS set.
import http from 'node:http';

const PORT = Number(process.argv[2] || process.env.VULN_PORT || 4100);

const server = http.createServer((req, res) => {
  const u = new URL(req.url, `http://127.0.0.1:${PORT}`);
  const q = u.searchParams;

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
  // 3. OS command injection — emit an `id`-command style output.
  if (q.has('ping')) {
    body += `<pre>PING ${q.get('ping')}\nuid=0(root) gid=0(root) groups=0(root)</pre>`;
  }
  // 4. SSRF — pretend to have fetched the attacker-supplied URL and leak a banner.
  if (q.has('url')) {
    body += `<pre>Response from ${q.get('url')}:\nSSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1</pre>`;
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
