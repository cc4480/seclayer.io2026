import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectChallengePage } from './challengePage.js';
import { compileStaticFindings } from './findings.js';

const page = (title: string, body = '') =>
  `<!doctype html><html><head><title>${title}</title></head><body>${body}</body></html>`;

test('detects a Cloudflare interstitial by title', () => {
  const v = detectChallengePage(403, page('Just a moment...'));
  assert.equal(v.isChallenge, true);
  assert.equal(v.vendor, 'Cloudflare');
});

test('detects vendor fingerprints in the body', () => {
  for (const [body, vendor] of [
    ['<script src="/cdn-cgi/challenge-platform/h/b/orchestrate"></script>', 'Cloudflare'],
    ['window._cf_chl_opt={};', 'Cloudflare'],
    ['<iframe src="https://geo.captcha-delivery.com/captcha/"></iframe>', 'DataDome'],
    ['Incapsula incident ID: 123-456', 'Imperva/Incapsula'],
    ['<img src="https://errors.edgesuite.net/x.gif">', 'Akamai'],
    ['token from awswaf.com', 'AWS WAF'],
  ] as const) {
    const v = detectChallengePage(200, page('Site', body));
    assert.equal(v.isChallenge, true, `${vendor} body signal must match`);
    assert.equal(v.vendor, vendor);
  }
});

test('a vendor header decides on its VALUE, not its presence', () => {
  // A site can serve its real homepage under x-datadome: protected — that means
  // the request PASSED. Treating the header itself as a verdict would mark a
  // working site as blocked while its content sits in the body.
  assert.equal(detectChallengePage(200, page('Real Site'), { 'x-datadome': 'protected' }).isChallenge, false);
  assert.equal(detectChallengePage(200, page('x'), { 'x-datadome': 'blocked' }).isChallenge, true);
  assert.equal(detectChallengePage(200, page('x'), { 'cf-mitigated': 'challenge' }).isChallenge, true);
});

test('a bare 403/503/429 with almost no body is an interception', () => {
  assert.equal(detectChallengePage(403, '<html><body>Forbidden</body></html>').isChallenge, true);
  assert.equal(detectChallengePage(503, '').isChallenge, true);
  assert.equal(detectChallengePage(429, 'rate limited').isChallenge, true);
});

test('does NOT fire on real pages — the expensive false direction', () => {
  // Suppressing a real scan is the failure this guards against, so pin it hard.
  const realPages: [number, string, Record<string, string>][] = [
    [200, page('Acme Corp — Home', '<h1>Welcome</h1><p>Please wait while we load your dashboard.</p>'), {}],
    [200, page('Security check your account settings', '<p>access denied to this folder</p>'), {}],
    [200, page('Blog — one more step to launch'), {}],
    // A big real page that merely loads a vendor script stays a real page.
    [200, page('Shop', '<script src="/cdn-cgi/challenge-platform/x"></script>' + 'x'.repeat(60_000)), {}],
    [403, page('Members Only', '<p>' + 'Real content explaining why access is restricted. '.repeat(80) + '</p>'), {}],
    [200, page('News'), { 'x-datadome': 'protected' }],
  ];
  for (const [status, html, headers] of realPages) {
    const v = detectChallengePage(status, html, headers);
    assert.equal(v.isChallenge, false, `must NOT flag: ${html.slice(0, 60)}`);
  }
});

test('an intercepted scan withholds content-derived findings and says so', () => {
  const base: any = {
    url: 'https://example.com', responseStatus: 403, sslSecure: true,
    headers: { server: 'cloudflare' },
    missingHeaders: ['content-security-policy', 'strict-transport-security', 'x-content-type-options'],
    techLeaked: ['cloudflare'], probedPaths: [],
    cookieIssues: ['Cookie "sessionid" is missing the Secure attribute'],
    cookieEvidence: { 'Cookie "sessionid" is missing the Secure attribute': 'sessionid=x' },
    sastFindings: [], scaFindings: [], scaLibraries: [], exposedConfigs: [], openRedirects: [],
    paramEndpoints: [], crawledPages: [], subdomains: [], dnsRecords: [],
    headerEvidence: {}, redirectChain: [], tlsInfo: {}, apiFindings: [], redTeamFindings: [],
    challenge: { isChallenge: true, vendor: 'Cloudflare', signal: 'interstitial title: "Just a moment..."' },
  };
  const out = compileStaticFindings(base);
  const titles = out.findings.map((f) => f.title);

  assert.ok(titles.some((t) => /intercepted by a bot-protection/i.test(t)), 'must explain the interception');
  // None of these describe example.com — they describe Cloudflare's page.
  for (const leaked of ['Missing Content-Security-Policy (CSP)', 'Missing Strict-Transport-Security (HSTS) Policy',
    'Missing X-Content-Type-Options (MIME Sniffing)', 'Verbose Server Framework Signature Leaked']) {
    assert.ok(!titles.includes(leaked), `must withhold "${leaked}" — it describes the interstitial`);
  }
  assert.ok(!titles.some((t) => /sessionid/i.test(t)), 'must withhold the challenge page\'s own cookies');
});

test('an ordinary scan is completely unaffected', () => {
  const base: any = {
    url: 'https://example.com', responseStatus: 200, sslSecure: true, headers: {},
    missingHeaders: ['content-security-policy'], techLeaked: [], probedPaths: [],
    cookieIssues: [], cookieEvidence: {},
    sastFindings: [], scaFindings: [], scaLibraries: [], exposedConfigs: [], openRedirects: [],
    paramEndpoints: [], crawledPages: [], subdomains: [], dnsRecords: [],
    headerEvidence: {}, redirectChain: [], tlsInfo: {}, apiFindings: [], redTeamFindings: [],
    challenge: { isChallenge: false, vendor: null, signal: null },
  };
  const titles = compileStaticFindings(base).findings.map((f) => f.title);
  assert.ok(titles.includes('Missing Content-Security-Policy (CSP)'), 'normal findings still report');
  assert.ok(!titles.some((t) => /intercepted/i.test(t)), 'no interception note on a normal scan');
});
