import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SENSITIVE_PROBES } from './perimeter.js';
import { compileStaticFindings } from './findings.js';

function probe(path: string) {
  const p = SENSITIVE_PROBES.find((x) => x.path === path);
  assert.ok(p, `expected a sensitive-path probe for ${path}`);
  return p!;
}

test('package-lock.json matcher fires on a real lockfile, not on HTML or package.json', () => {
  const p = probe('/package-lock.json');
  assert.equal(p.matches('{"name":"app","lockfileVersion":3,"requires":true,"packages":{}}'), true);
  // SPA fallback (index.html served for an unknown path) — the dominant FP.
  assert.equal(p.matches('<!doctype html><html><body>app</body></html>'), false);
  // package.json is not the lockfile — no lockfileVersion key.
  assert.equal(p.matches('{"name":"app","version":"1.0.0","dependencies":{}}'), false);
});

test('yarn / pnpm / composer / Gemfile lockfile matchers fire on their real signatures', () => {
  assert.equal(probe('/yarn.lock').matches('# yarn lockfile v1\n\n\nfoo@^1.0.0:\n  version "1.2.3"'), true);
  assert.equal(probe('/pnpm-lock.yaml').matches("lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true"), true);
  assert.equal(probe('/composer.lock').matches('{\n  "_readme": [],\n  "content-hash": "abc123",\n  "packages": []\n}'), true);
  assert.equal(probe('/Gemfile.lock').matches('GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.1.0)\n\nDEPENDENCIES\n  rails\n'), true);
  // None of them fire on an HTML SPA fallback.
  for (const path of ['/yarn.lock', '/pnpm-lock.yaml', '/composer.lock', '/Gemfile.lock']) {
    assert.equal(probe(path).matches('<!doctype html><html></html>'), false, `${path} must reject HTML`);
  }
});

test('.npmrc probe fires only when an auth token is actually present (credential leak)', () => {
  const p = probe('/.npmrc');
  assert.equal(p.matches('//registry.npmjs.org/:_authToken=npm_aBcD1234EfGh5678'), true);
  // A plain .npmrc with no token is config, not a credential leak — must NOT fire.
  assert.equal(p.matches('registry=https://registry.npmjs.org/\nsave-exact=true'), false);
});

test('exposed lockfile compiles to LOW and a .npmrc token to HIGH — not the generic critical/high', () => {
  const diag = {
    url: 'https://target.test', scannedAt: '', responseStatus: 200, sslSecure: true,
    headers: {}, missingHeaders: [], techLeaked: [], cookieIssues: [],
    sastFindings: [], scaLibraries: [], redTeamFindings: [], apiSecFindings: [],
    easmPerimeter: { subdomains: [], ip: '', nameserver: '', protocol: 'HTTPS' },
    activeProbesSkipped: false,
    probedPaths: [
      { path: '/package-lock.json', status: 200, exposed: true, meta: probe('/package-lock.json').meta },
      { path: '/.npmrc', status: 200, exposed: true, meta: probe('/.npmrc').meta },
    ],
  } as any;
  const { findings } = compileStaticFindings(diag);
  const lock = findings.find((f) => /package-lock\.json/.test(f.title));
  const npmrc = findings.find((f) => /\.npmrc/.test(f.title));
  assert.ok(lock, 'expected a package-lock.json finding');
  assert.equal(lock!.severity, 'low', 'lockfile exposure must be LOW, not the generic high');
  assert.ok(npmrc, 'expected a .npmrc finding');
  assert.equal(npmrc!.severity, 'high', '.npmrc auth-token leak must be HIGH');
});
