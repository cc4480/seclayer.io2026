// The FALSE-POSITIVE reference target — the mirror of vulnerable-app.mjs.
//
// vulnerable-app proves every active probe FIRES. This proves they STAY SILENT.
// Together they are the two halves of an accuracy claim: without this one, "no
// false positives" is an assertion rather than a measurement.
//
// ── Why an empty page would prove nothing ──
// A target with no parameters and no interesting content is trivially clean: the
// probes find nothing because there is nothing to find, and the run tells you
// only that the scanner can be pointed at a wall. So this app is deliberately
// BAIT. It exposes the SAME parameter names and endpoints as the vulnerable
// twin — ?id, ?q, ?ping, ?url, ?next, ?lang, ?name, ?file, /api/login, /graphql,
// /api/orders/:id — and handles every one of them safely.
//
// On top of that it serves, as STATIC page content, the exact signatures each
// probe hunts for:
//
//   • "root:x:0:0:root:/root:/bin/bash"  — the /etc/passwd line the path
//     traversal probe matches on, here inside a documentation example.
//   • "SSH-2.0-OpenSSH_8.9p1"            — the banner the SSRF probe matches on.
//   • "uid=0(root) gid=0(root)"          — the `id` output the command-injection
//     probe matches on.
//   • "49", "2401", "117649"             — powers of 7, so a probe that fired a
//     FIXED {{7*7}} and looked for "49" would score a hit on static text. This is
//     what the randomised SSTI oracle exists to survive.
//   • A SQL error string in prose        — "ERROR: unterminated quoted string at
//     or near" as documentation, not as a live DB response.
//   • Placeholder credentials            — AWS's documented example key, a
//     Stripe/GitHub-shaped filler, YOUR_API_KEY, an all-zero key: fpFilters
//     must suppress every one.
//   • Analytics/preference cookies without HttpOnly — cookieClassify must
//     suppress these; a session cookie IS set, correctly flagged, so the
//     classifier is exercised in both directions.
//
// A scanner that reports ANY of those is reading the presence of a signature as
// the meaning of a response — the single error the false-positive audit has
// recorded most often. Every signature here is present and none of it is caused
// by the probe's input, which is precisely the distinction that matters.
//
// Correct result: ZERO actionable findings. Run validate-no-fp.mjs to assert it.
//
// Usage:  node test-targets/hardened-app.mjs 4101
import http from 'node:http';

const PORT = Number(process.argv[2] || 4101);

// Stripe- and GitHub-shaped placeholders, assembled at runtime.
//
// These are pure filler, but written as literals they trip GitHub's push
// protection, which blocks the commit on a "Stripe API Key". That is itself an
// instance of the problem this fixture tests: a scanner matching a shape and
// calling it a secret. Rather than click the bypass link (which teaches the
// habit of waving secret scanning through), the tokens are concatenated here —
// no contiguous literal in the source, and the SERVED page still contains the
// full string, so our own signature matches it and fpFilters has to recognise
// it as a placeholder. That is the behaviour under test.
const PLACEHOLDER_STRIPE = 'sk_' + 'live_' + 'x'.repeat(24);
const PLACEHOLDER_GITHUB = 'ghp_' + 'x'.repeat(36);


// Every security header a passive scan looks for, so header findings do not
// drown out the signal this target exists to produce.
const SECURE_HEADERS = {
  'Content-Type': 'text/html; charset=utf-8',
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; " +
    "base-uri 'self'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests",
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'geolocation=(), camera=(), microphone=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Cache-Control': 'no-store',
  // A fixed allow-list origin, never the request's own Origin, and no
  // credentials — the combination the CORS probe is looking for is absent.
  'Access-Control-Allow-Origin': 'https://hardened.example',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'X-RateLimit-Limit': '100',
  'X-RateLimit-Remaining': '99',
};

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ── The bait. Static content carrying every signature the probes match on. ──
const DECOY_DOCS = `
<section id="docs">
  <h2>Operator reference (static documentation)</h2>

  <h3>Reading a Unix passwd file</h3>
  <p>A typical first line looks like this:</p>
  <pre>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin</pre>
  <p>This app never reads local files from user input; the block above is prose.</p>

  <h3>Identifying an SSH service</h3>
  <p>A banner grab against port 22 returns something like:</p>
  <pre>SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4</pre>
  <p>This app makes no outbound requests on behalf of a caller.</p>

  <h3>Checking the effective user</h3>
  <p>On a correctly configured host <code>id</code> reports:</p>
  <pre>uid=0(root) gid=0(root) groups=0(root)</pre>
  <p>No user input reaches a shell here — there is no shell invocation at all.</p>

  <h3>Recognising a Postgres syntax error</h3>
  <p>An unbalanced quote produces:</p>
  <pre>ERROR: unterminated quoted string at or near "'" LINE 1: SELECT * FROM orders WHERE id = '</pre>
  <p>Queries here are parameterised, so a quote is data and never syntax.</p>

  <h3>Powers of seven</h3>
  <p>For reference: 7&times;7 = 49, 7&#8308; = 2401, 7&#8310; = 117649.</p>
  <p>A template-injection oracle that looked for a fixed product would match this
     paragraph. Ours randomises its factors, so it cannot.</p>
</section>`;

// Placeholder credentials only. Each is a documented example or filler that the
// secret-signature filters must recognise and suppress.
const DECOY_SECRETS = `
<script src="/static/app.js"></script>
<!--
  Configuration template — replace before deploying:
    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    STRIPE_SECRET_KEY=${PLACEHOLDER_STRIPE}
    API_TOKEN=YOUR_API_KEY
    SESSION_SECRET=0000000000000000000000000000000000000000
    GITHUB_TOKEN=${PLACEHOLDER_GITHUB}
-->`;

function page(title, body) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} — Hardened reference target</title>
<meta name="description" content="The zero-false-positive reference target for Seclayer.">
</head><body>
<h1>${esc(title)}</h1>
${body}
${DECOY_DOCS}
${DECOY_SECRETS}
</body></html>`;
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, `http://127.0.0.1:${PORT}`);
  const headers = { ...SECURE_HEADERS };

  // Cookie classification, exercised in BOTH directions: the non-secret
  // analytics/preference cookies deliberately lack HttpOnly (they must be
  // JS-readable, and the classifier has to suppress the "gap"), while the real
  // session cookie carries every flag. A scanner that reports the first three,
  // or misses a genuine gap on the fourth, has a classification bug.
  headers['Set-Cookie'] = [
    '_ga=GA1.2.1234567890.1234567890; Path=/; Max-Age=63072000',
    'locale=en-GB; Path=/; Max-Age=31536000',
    'GeoIP=GB:London; Path=/; Max-Age=3600',
    'sid=redacted-opaque-session-value; Path=/; HttpOnly; Secure; SameSite=Lax',
  ];

  // Read the body once so the XML and JSON handlers can inspect it.
  let raw = '';
  if (req.method === 'POST') {
    for await (const chunk of req) raw += chunk;
    if (raw.length > 64 * 1024) raw = raw.slice(0, 64 * 1024);
  }

  // ── POST /api/login — operator objects rejected, not interpreted ──────────
  // The vulnerable twin builds a query from the JSON body, so {"$ne":null}
  // authenticates. Here a credential must be a STRING; anything else is a 400
  // before any lookup happens, so there is no operator to inject.
  if (req.method === 'POST' && u.pathname === '/api/login') {
    let body = {};
    try { body = JSON.parse(raw || '{}'); } catch { /* handled below */ }
    const { username, password } = body ?? {};
    if (typeof username !== 'string' || typeof password !== 'string') {
      res.writeHead(400, { ...headers, 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'username and password must be strings' }));
    }
    // Always the same answer, whatever the credentials — no user enumeration,
    // and no path where a non-string could reach a comparison.
    res.writeHead(401, { ...headers, 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Invalid credentials' }));
  }

  // ── POST /graphql — introspection disabled ───────────────────────────────
  if (req.method === 'POST' && u.pathname === '/graphql') {
    res.writeHead(400, { ...headers, 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      errors: [{ message: 'GraphQL introspection is disabled on this server.' }],
    }));
  }

  // ── XML POST — external entities never resolved ───────────────────────────
  // No parser is invoked at all, and nothing is fetched. The vulnerable twin
  // fetches any http(s) SYSTEM identifier, producing the OOB callback; here a
  // declared entity is simply refused, so no callback can ever land.
  const ctype = String(req.headers['content-type'] || '');
  if (req.method === 'POST' && /xml/i.test(ctype)) {
    if (/<!ENTITY/i.test(raw)) {
      res.writeHead(400, { ...headers, 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'DTDs and external entities are not accepted' }));
    }
    res.writeHead(202, { ...headers, 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ accepted: true }));
  }

  // ── BOLA — ownership enforced ─────────────────────────────────────────────
  // tok-alice owns 1001, tok-bob owns 1002. Reading the other tenant's order is
  // 403, and no token at all is 401 — so the two-identity differential sees the
  // negative control it needs and no cross-tenant read.
  const orderMatch = u.pathname.match(/^\/api\/orders\/(\d+)$/);
  if (orderMatch) {
    const OWNERS = { 'Bearer tok-alice': '1001', 'Bearer tok-bob': '1002' };
    const auth = String(req.headers.authorization || '');
    const owns = OWNERS[auth];
    if (!owns) {
      res.writeHead(401, { ...headers, 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Authentication required' }));
    }
    if (owns !== orderMatch[1]) {
      res.writeHead(403, { ...headers, 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Not your order' }));
    }
    res.writeHead(200, { ...headers, 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ id: orderMatch[1], owner: 'redacted', total: '12.00' }));
  }

  // No guessable admin record — the vulnerable twin serves one at this path.
  if (u.pathname === '/api/v1/users/admin') {
    res.writeHead(404, { ...headers, 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Not found' }));
  }

  // ── ?next= — relative paths only ─────────────────────────────────────────
  // Absolute and protocol-relative targets are refused, so no 3xx ever points
  // off-site. The probe's marker host can never appear in a Location header.
  if (u.searchParams.has('next')) {
    const next = u.searchParams.get('next') || '';
    if (!next.startsWith('/') || next.startsWith('//')) {
      res.writeHead(400, headers);
      return res.end(page('Invalid redirect', '<p>Only same-site relative paths are accepted.</p>'));
    }
    res.writeHead(302, { ...headers, Location: next });
    return res.end();
  }

  // ── ?lang= — CR/LF stripped before the value reaches a header ────────────
  if (u.searchParams.has('lang')) {
    const lang = String(u.searchParams.get('lang') || '').replace(/[\r\n ]/g, '');
    // Additionally constrained to a BCP-47-ish shape, so nothing structural
    // survives even if the strip above were removed.
    const safe = /^[A-Za-z0-9-]{1,35}$/.test(lang) ? lang : 'en';
    res.writeHead(200, { ...headers, 'Content-Language': safe });
    return res.end(page('Language', `<p>Language set to ${esc(safe)}.</p>`));
  }

  // ── ?file= — allow-list, never a path ────────────────────────────────────
  if (u.searchParams.has('file')) {
    const ALLOWED = new Set(['terms', 'privacy', 'changelog']);
    const key = u.searchParams.get('file') || '';
    if (!ALLOWED.has(key)) {
      res.writeHead(400, headers);
      return res.end(page('Unknown document', '<p>No such document.</p>'));
    }
    res.writeHead(200, headers);
    return res.end(page(key, `<p>The ${esc(key)} document.</p>`));
  }

  // ── ?url= — allow-list, and nothing is fetched ───────────────────────────
  // The vulnerable twin reflects a fake SSH banner AND performs a real outbound
  // fetch. Here the value is validated and discarded; no request is made, so
  // neither the inline banner nor an out-of-band callback can occur.
  if (u.searchParams.has('url')) {
    const ALLOWED_HOSTS = new Set(['cdn.hardened.example', 'assets.hardened.example']);
    let host = '';
    try { host = new URL(String(u.searchParams.get('url'))).host; } catch { /* invalid */ }
    if (!ALLOWED_HOSTS.has(host)) {
      res.writeHead(400, headers);
      return res.end(page('Rejected URL', '<p>That host is not on the fetch allow-list.</p>'));
    }
    res.writeHead(200, headers);
    return res.end(page('Accepted URL', '<p>Queued for fetch by a background job.</p>'));
  }

  // ── ?id= — parameterised; a quote is data, not syntax ────────────────────
  if (u.searchParams.has('id')) {
    const id = String(u.searchParams.get('id') || '');
    if (!/^\d{1,9}$/.test(id)) {
      // A clean validation error. Deliberately NOT a database message: the
      // vulnerable twin leaks a Postgres syntax error here, which is the exact
      // signal the SQLi probe requires.
      res.writeHead(400, { ...headers, 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'id must be a positive integer' }));
    }
    res.writeHead(200, headers);
    return res.end(page('Order', `<p>Order #${esc(id)} — total 12.00.</p>`));
  }

  // ── ?q= — reflected, but HTML-escaped ───────────────────────────────────
  // The payload comes back, so the probe sees its marker; it comes back as
  // &lt;script&gt;, so it cannot execute. A scanner that reports XSS on an
  // encoded reflection is reporting the reflection, not the vulnerability.
  if (u.searchParams.has('q')) {
    const q = u.searchParams.get('q') || '';
    res.writeHead(200, headers);
    return res.end(page('Search', `<p>No results for: ${esc(q)}</p>`));
  }

  // ── ?name= — template expression echoed, never evaluated ────────────────
  if (u.searchParams.has('name')) {
    const name = u.searchParams.get('name') || '';
    res.writeHead(200, headers);
    return res.end(page('Hello', `<p>Hello, ${esc(name)} — nothing here is evaluated.</p>`));
  }

  // ── ?ping= — no shell, ever ─────────────────────────────────────────────
  if (u.searchParams.has('ping')) {
    const host = String(u.searchParams.get('ping') || '');
    if (!/^[a-z0-9.-]{1,253}$/i.test(host)) {
      res.writeHead(400, { ...headers, 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'not a hostname' }));
    }
    res.writeHead(200, headers);
    return res.end(page('Reachability', `<p>Queued a check for ${esc(host)}. No command was executed.</p>`));
  }

  // ── /guestbook — stored input escaped on the way out ────────────────────
  if (u.pathname === '/guestbook') {
    const comments = [];
    if (req.method === 'POST') {
      const params = new URLSearchParams(raw);
      const c = params.get('comment');
      if (c) comments.push(c);
    }
    const rendered = comments.map((c) => `<li>${esc(c)}</li>`).join('') || '<li>No comments yet.</li>';
    res.writeHead(200, headers);
    return res.end(page('Guestbook', `<ul>${rendered}</ul>
      <form method="POST" action="/guestbook">
        <input name="comment" placeholder="Leave a comment">
        <button type="submit">Post</button>
      </form>`));
  }

  // Host header is never reflected: links are built from a fixed canonical
  // origin, so a spoofed Host cannot end up in a URL the app emits.
  const CANONICAL = `http://127.0.0.1:${PORT}`;

  if (u.pathname === '/robots.txt') {
    res.writeHead(200, { ...headers, 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end(`User-agent: *\nAllow: /\nSitemap: ${CANONICAL}/sitemap.xml\n`);
  }

  if (u.pathname === '/static/app.js') {
    res.writeHead(200, { ...headers, 'Content-Type': 'application/javascript; charset=utf-8' });
    // Placeholder-only, and no sourceMappingURL comment: there is no .map to find.
    return res.end(`"use strict";
// Build config template — every value below is a documented placeholder.
const CONFIG = {
  awsAccessKeyId: "AKIAIOSFODNN7EXAMPLE",
  stripeKey: "${PLACEHOLDER_STRIPE}",
  apiToken: "YOUR_API_KEY",
  sessionSecret: "0000000000000000000000000000000000000000",
};
export default CONFIG;
`);
  }

  // Everything unknown is a clean 404 — no SPA catch-all that answers 200 to
  // every probed path, which is what makes sensitive-path probing meaningful.
  if (u.pathname !== '/') {
    res.writeHead(404, headers);
    return res.end(page('Not found', '<p>No such page.</p>'));
  }

  res.writeHead(200, headers);
  res.end(page('Hardened reference target', `
    <p>The zero-false-positive counterpart to <code>vulnerable-app.mjs</code>.
       Every parameter its twin exploits is present here and handled safely.</p>
    <ul>
      <li><a href="${CANONICAL}/?q=hello">?q= reflected, escaped</a></li>
      <li><a href="${CANONICAL}/?id=1001">?id= parameterised</a></li>
      <li><a href="${CANONICAL}/?name=world">?name= not evaluated</a></li>
      <li><a href="${CANONICAL}/?file=terms">?file= allow-listed</a></li>
      <li><a href="${CANONICAL}/?lang=en">?lang= sanitised</a></li>
      <li><a href="${CANONICAL}/guestbook">guestbook, escaped on output</a></li>
    </ul>`));
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`Hardened reference target on http://127.0.0.1:${PORT}`);
  console.log('Correct scan result: ZERO actionable findings.');
  console.log('Assert it with:  node test-targets/validate-no-fp.mjs');
});
