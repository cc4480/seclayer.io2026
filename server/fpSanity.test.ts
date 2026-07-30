// False-positive sanity harness: models what the PASSIVE scan produces for
// well-secured, real-world-shaped sites and asserts the engine reports ZERO
// false positives. This is the offline, deterministic stand-in for a live scan
// of hardened sites (github.com, cloudflare.com, mozilla.org and the like) — it
// exercises the real detectors, not mocks, and guards against a future change
// re-introducing a false positive on a clean site.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeSecrets, analyzeLibraries } from './staticAnalysis.js';
import { compileStaticFindings } from './findings.js';

function baseDiag(overrides: any = {}): any {
  return {
    url: 'https://secure.example', scannedAt: '', responseStatus: 200, sslSecure: true,
    headers: {}, missingHeaders: [], techLeaked: [], probedPaths: [], cookieIssues: [],
    sastFindings: [], scaLibraries: [], easmPerimeter: { subdomains: [], ip: '', nameserver: '', protocol: 'HTTPS' },
    redTeamFindings: [], apiSecFindings: [], activeProbesSkipped: true, ...overrides,
  };
}

// Markup a modern, well-maintained site serves: current library versions loaded
// via <script src>, and only placeholder/example credentials in view.
const HARDENED_HTML = `<!doctype html><html><head>
  <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
  <link href="https://cdn.example/bootstrap-5.3.3.min.css" rel="stylesheet">
  <script src="https://cdn.example/lodash@4.17.21/lodash.min.js"></script>
  <script>const docsKey = "YOUR_API_KEY"; const sample = "sk_live_000000000000000000000000";</script>
</head><body><p>See jquery-1.9 migration notes in our changelog.</p></body></html>`;

test('SANITY: no vulnerable-library false positives on a site running current versions', () => {
  // jQuery 3.7.1, Bootstrap 5.x, lodash 4.17.21 are all patched. The "jquery-1.9"
  // in prose must NOT be misread as a loaded dependency.
  assert.deepEqual(analyzeLibraries(HARDENED_HTML), [], 'current libraries must not be flagged');
});

test('SANITY: no secret false positives from placeholder/example credentials', () => {
  assert.deepEqual(analyzeSecrets(HARDENED_HTML), [], 'placeholder/filler credentials must be screened out');
});

// Profile A: a site that protects framing with CSP frame-ancestors and omits the
// legacy X-Frame-Options header (extremely common on hardened sites). Modeled as
// a verified scan whose active probes found nothing, so a clean site scores 100.
test('SANITY: clean site using CSP frame-ancestors yields no false positives', () => {
  const diag = baseDiag({
    sslSecure: true,
    activeProbesSkipped: false, // probes ran and found nothing
    // X-Frame-Options absent, but CSP + frame-ancestors present, HSTS present,
    // nosniff present, referrer-policy present.
    missingHeaders: ['x-frame-options'],
    headers: {
      'content-security-policy': "default-src 'self'; frame-ancestors 'none'; script-src 'self'",
      'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin',
    },
    // A SPA that returns 200 + index.html for unknown paths: the body does NOT
    // match any sensitive-file signature, so nothing is "exposed".
    probedPaths: [
      { path: '/.env', status: 200, exposed: false },
      { path: '/.git/config', status: 404, exposed: false },
      { path: '/config.json', status: 200, exposed: false },
    ],
  });
  const r = compileStaticFindings(diag);
  assert.deepEqual(
    r.findings.map((f) => f.title), [],
    `a hardened site must yield no findings, got: ${r.findings.map((f) => `[${f.severity}] ${f.title}`).join(', ')}`,
  );
  assert.equal(r.score, 100, 'a clean site scores 100');
});

// Profile B: a fully-headered HTTPS site with secure cookies produces nothing.
test('SANITY: fully-hardened HTTPS site with secure cookies is clean', () => {
  const diag = baseDiag({
    sslSecure: true,
    activeProbesSkipped: false,
    missingHeaders: [], // every tracked header present
    cookieIssues: [],   // Secure + HttpOnly set on all cookies
    scaLibraries: [],
    sastFindings: [],
    probedPaths: [{ path: '/.env', status: 404, exposed: false }],
  });
  const r = compileStaticFindings(diag);
  assert.deepEqual(r.findings.map((f) => f.title), [], 'no false positives on a fully-hardened site');
  assert.equal(r.score, 100);
});
