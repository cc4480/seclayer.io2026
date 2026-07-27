// INTENTIONALLY VULNERABLE test target — for exercising Seclayer's active
// red-team AND aggressive-tier probes against a local app you own. NOT for
// production. It only *simulates* vulnerable responses (it never actually runs
// SQL, shells out, reads files, or parses XML) so it is safe to run, while still
// tripping each probe signature the scanner looks for. The ONE real side effect
// is deliberate blind-SSRF/XXE: it fetches an attacker-supplied http(s) URL
// server-side so the out-of-band collaborator probe has something to catch.
//
//   node test-targets/vulnerable-app.mjs [port]
//
// Then point Seclayer at http://127.0.0.1:<port> with SCAN_DEV_ALLOW_HOSTS set.
//
// Coverage (one dedicated param/endpoint per class so every probe fires cleanly):
//   Red team:   ?id (SQLi), ?q (XSS), ?ping (cmd), ?url (SSRF + blind OOB),
//               POST /graphql (introspection), /api/v1/users/admin (exposed obj),
//               /api/orders/:id (BOLA, two identities)
//   Aggressive: ?name (SSTI), ?file (LFI), ?next (open redirect), ?lang (CRLF),
//               Origin header (CORS), POST xml (XXE OOB), POST /api/login (NoSQL)
//   Discovered POST form (VULN_EXPOSE_SURFACE=1): a crawlable <form method=POST
//               action=/submit-review> with fields q (XSS) + id (SQLi) whose
//               body feeds the same reflective sinks, validating POST-body
//               discovered-parameter fuzzing alongside the GET-link surface.
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
  // Buffer the request body so the XXE / NoSQL simulations can inspect POST data.
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    try {
      handle(req, res, Buffer.concat(chunks).toString('utf8'));
    } catch {
      if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('error');
    }
  });
});

function handle(req, res, rawBody) {
  const u = new URL(req.url, `http://127.0.0.1:${PORT}`);
  const q = u.searchParams;

  // Reflective CORS misconfiguration (applied to EVERY response): echo the
  // request Origin into Access-Control-Allow-Origin AND allow credentials — the
  // exact dangerous combination the CORS probe looks for.
  const cors = {};
  if (req.headers['origin']) {
    cors['Access-Control-Allow-Origin'] = req.headers['origin'];
    cors['Access-Control-Allow-Credentials'] = 'true';
  }

  // XXE — any POST with an XML content-type: if the body declares an external
  // entity with an http(s) SYSTEM identifier, "resolve" it by fetching that URL
  // server-side (fire-and-forget), producing the out-of-band callback the XXE
  // probe waits for.
  if (req.method === 'POST' && /xml/i.test(req.headers['content-type'] || '')) {
    const m = /<!ENTITY\s+\S+\s+SYSTEM\s+["']([^"']+)["']/i.exec(rawBody || '');
    if (m && /^https?:\/\//i.test(m[1])) fetch(m[1]).catch(() => {});
    res.writeHead(200, { 'Content-Type': 'application/xml', ...cors });
    res.end('<root>ok</root>');
    return;
  }

  // NoSQL operator-injection login — builds its "query" straight from the JSON
  // body: benign string creds fail, but an operator object ({"$ne":null}) matches
  // any user and authenticates. Trips the NoSQL differential probe.
  if (req.method === 'POST' && u.pathname === '/api/login') {
    let authed = false;
    try {
      const c = JSON.parse(rawBody || '{}');
      const isOp = (v) => v !== null && typeof v === 'object';
      authed = isOp(c.username) || isOp(c.password)
        ? true
        : (c.username === 'admin' && c.password === 'correct-horse');
    } catch { authed = false; }
    res.writeHead(200, { 'Content-Type': 'application/json', ...cors });
    res.end(JSON.stringify(authed
      ? { authenticated: true, token: 'sess_' + Math.random().toString(16).slice(2) }
      : { authenticated: false }));
    return;
  }

  // 6. GraphQL introspection — a production endpoint with introspection left ON.
  if (req.method === 'POST' && u.pathname === '/graphql') {
    res.writeHead(200, { 'Content-Type': 'application/json', ...cors });
    res.end(JSON.stringify({
      data: { __schema: { types: [
        { name: 'Query' }, { name: 'Mutation' }, { name: 'User' },
        { name: 'Order' }, { name: 'Payment' }, { name: 'AdminSecret' },
      ] } },
    }));
    return;
  }

  // 7. Exposed user-object endpoint — a protected admin record at a guessable path.
  if (u.pathname === '/api/v1/users/admin') {
    res.writeHead(200, { 'Content-Type': 'application/json', ...cors });
    res.end(JSON.stringify({ user: { id: 1, username: 'admin', email: 'admin@vulnshop.test', role: 'superadmin' } }));
    return;
  }

  // 5. BOLA / IDOR — any valid token can read any order id; unauth → 401.
  const om = u.pathname.match(/^\/api\/orders\/(\d+)$/);
  if (om) {
    const tok = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
    if (!tok) { res.writeHead(401, { 'Content-Type': 'application/json', ...cors }); res.end('{"error":"unauthorized"}'); return; }
    const o = ORDERS[om[1]];
    if (!o) { res.writeHead(404, { 'Content-Type': 'application/json', ...cors }); res.end('{"error":"not found"}'); return; }
    res.writeHead(200, { 'Content-Type': 'application/json', ...cors }); res.end(JSON.stringify(o)); return;
  }

  // Open redirect — ?next= is used verbatim as the redirect target. (CRLF is
  // stripped here so this simulates ONLY an open redirect, not response-splitting.)
  if (q.has('next')) {
    const loc = String(q.get('next')).replace(/[\r\n]/g, '');
    res.writeHead(302, { Location: loc, ...cors });
    res.end();
    return;
  }

  // CRLF / response-header injection — the ?lang= value is written into the
  // response headers unsanitized, so an embedded CRLF injects a new header.
  const injectedHeaders = {};
  if (q.has('lang')) {
    const lines = String(q.get('lang')).split(/\r\n|\n/);
    for (let i = 1; i < lines.length; i++) {
      const hm = /^([A-Za-z0-9-]+):\s?(.*)$/.exec(lines[i]);
      if (hm) injectedHeaders[hm[1]] = hm[2];
    }
  }

  let body = `<!doctype html><html><head><title>Vulnerable Test App</title></head>`
    + `<body><h1>Intentionally Vulnerable Test Target</h1>`
    + `<p>For local Seclayer red-team probe testing only.</p>`;

  // Discoverable parameterized links (for validating DISCOVERED-parameter fuzzing)
  // are OFF by default so a plain red-team scan of this target stays clean — no
  // crawler-discovered surface, no extra discovered-parameter findings. Opt in
  // ONLY for the aggressive discovered-param validation:
  //   VULN_EXPOSE_SURFACE=1 node test-targets/vulnerable-app.mjs 4100
  if (process.env.VULN_EXPOSE_SURFACE === '1') {
    body += `<nav>`
      + `<a href="/item?id=1">Item</a> `
      + `<a href="/find?q=test">Find</a> `
      + `<a href="/search?name=demo">Search</a> `
      + `<a href="/view?file=readme.txt">View</a> `
      + `<a href="/go?next=/home">Continue</a> `
      + `<a href="/prefs?lang=en">Language</a>`
      + `</nav>`;
    // A crawlable POST <form> so DISCOVERED-parameter fuzzing is exercised over a
    // form body, not just GET query strings. Its fields (q, id) map to the same
    // reflective sinks below via the form-body merge, so the fuzzer's POST
    // payloads confirm XSS/SQLi on /submit-review exactly as on a GET link.
    body += `<form method="POST" action="/submit-review">`
      + `<input name="q" placeholder="review">`
      + `<input name="id" placeholder="ref">`
      + `<button type="submit">Submit review</button></form>`;
  }

  // Form-encoded POST bodies feed the SAME reflective sinks as GET query params,
  // so a crawler-discovered POST <form> (see VULN_EXPOSE_SURFACE above) exercises
  // injection exactly like a GET link — this is what lets validate-probes assert
  // POST-body discovered-parameter fuzzing. Placed AFTER the open-redirect/CRLF
  // handlers, which stay GET-only to match the scanner's own POST policy.
  if (req.method === 'POST' && /application\/x-www-form-urlencoded/i.test(req.headers['content-type'] || '')) {
    for (const [k, v] of new URLSearchParams(rawBody || '')) q.set(k, v);
  }

  // 1. SQL injection — DB error ONLY when the value breaks the query (a quote);
  //    a benign numeric id returns a normal row (so the differential probe fires).
  if (q.has('id')) {
    const id = q.get('id');
    if (/['"]/.test(id)) {
      body += `<div class="err">Database error: You have an error in your SQL syntax; `
        + `check the manual that corresponds to your MySQL server version near `
        + `'${id}' at line 1</div>`;
    } else {
      body += `<div class="results">Order #${id}: status=shipped, total=$42.00</div>`;
    }
  }
  // 2. Reflected XSS — echo `q` back completely unescaped.
  if (q.has('q')) {
    body += `<div class="results">Search results for: ${q.get('q')}</div>`;
  }
  // 3. OS command injection — arithmetic oracle + `id` output signature.
  if (q.has('ping')) {
    const ping = q.get('ping');
    let out = `PING ${ping}`;
    const expr = /expr\s+(\d+)\s*\+\s*(\d+)/.exec(ping);
    if (expr) out += `\n${Number(expr[1]) + Number(expr[2])}`;
    if (/;\s*id\b/.test(ping)) out += `\nuid=0(root) gid=0(root) groups=0(root)`;
    body += `<pre>${out}</pre>`;
  }
  // 4. SSRF — reflected SSH banner; also actually fetch a real http(s) URL that
  //    isn't the simulated loopback:22, so the blind-OOB probe records a callback.
  if (q.has('url')) {
    const target = q.get('url');
    if (/^https?:\/\//i.test(target) && !/127\.0\.0\.1:22/.test(target)) {
      fetch(target).catch(() => {});
    }
    body += `<pre>Response from ${target}:\nSSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1</pre>`;
  }
  // 8. SSTI — a "template engine" that evaluates a simple A*B inside template
  //    markers ({{ }}, ${ }, #{ }, <%= %>), returning the computed product.
  if (q.has('name')) {
    const name = q.get('name');
    const m = /(?:\{\{|\$\{|#\{|<%=)\s*(\d+)\s*\*\s*(\d+)\s*(?:\}\}|\}|%>)/.exec(name);
    body += `<div>Hello ${m ? Number(m[1]) * Number(m[2]) : name}</div>`;
  }
  // 9. Path traversal / LFI — return /etc/passwd content for any traversal to it.
  if (q.has('file') && /etc\/passwd/i.test(String(q.get('file')))) {
    body += `<pre>root:x:0:0:root:/root:/bin/bash\n`
      + `daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n`
      + `www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin</pre>`;
  }

  body += `</body></html>`;

  // Deliberately omit every security header (CSP/HSTS/X-Frame-Options/etc.) so
  // the passive IAST checks also flag this target. `injectedHeaders` carries any
  // CRLF-injected header; `cors` carries the reflected-origin CORS headers.
  res.writeHead(200, { 'Content-Type': 'text/html', 'Server': 'VulnTestApp/1.0', ...cors, ...injectedHeaders });
  res.end(body);
}

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[vuln-app] intentionally-vulnerable target listening on http://127.0.0.1:${PORT}`);
});
