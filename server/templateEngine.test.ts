import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchResponse, runTemplate, runTemplates, Template, ResponseView } from './templateEngine.js';
import { TEMPLATES } from './templates.js';

const view = (o: Partial<ResponseView>): ResponseView => ({ status: 200, body: '', headers: '', ...o });

test('status matcher', () => {
  assert.equal(matchResponse([{ type: 'status', status: [200, 204] }], 'and', view({ status: 200 })), true);
  assert.equal(matchResponse([{ type: 'status', status: [200] }], 'and', view({ status: 404 })), false);
});

test('word matcher with or/and conditions', () => {
  const r = view({ body: 'services:\n image: nginx' });
  assert.equal(matchResponse([{ type: 'word', words: ['services:', 'nope'], condition: 'or' }], 'and', r), true);
  assert.equal(matchResponse([{ type: 'word', words: ['services:', 'image:'], condition: 'and' }], 'and', r), true);
  assert.equal(matchResponse([{ type: 'word', words: ['services:', 'absent'], condition: 'and' }], 'and', r), false);
});

test('negative matcher excludes SPA html fallback', () => {
  const spa = view({ status: 200, body: '<!doctype html><html><head></head></html>' });
  const m = [
    { type: 'status' as const, status: [200] },
    { type: 'word' as const, words: ['FROM '] },
    { type: 'word' as const, words: ['<!doctype', '<html'], negative: true },
  ];
  assert.equal(matchResponse(m, 'and', spa), false); // html present -> negative fails -> no match
  const real = view({ status: 200, body: 'FROM node:22\nRUN npm ci' });
  assert.equal(matchResponse(m, 'and', real), true);
});

test('regex and header part matchers', () => {
  assert.equal(matchResponse([{ type: 'regex', regex: '^[A-Z_]+=' }], 'and', view({ body: 'DB_PASSWORD=secret' })), true);
  assert.equal(
    matchResponse([{ type: 'word', part: 'header', words: ['x-powered-by'] }], 'and', view({ headers: 'x-powered-by: php\n' })),
    true,
  );
});

test("matchersCondition 'or' matches when any matcher passes", () => {
  const r = view({ status: 500, body: 'Adminer' });
  assert.equal(matchResponse([{ type: 'status', status: [200] }, { type: 'word', words: ['Adminer'] }], 'or', r), true);
});

test('runTemplate returns a finding only on a real match', async () => {
  const tpl: Template = {
    id: 't', name: 'Test Panel', severity: 'high', category: 'DAST',
    description: 'desc', fix: 'fix',
    requests: [{ path: '/panel', matchers: [{ type: 'status', status: [200] }, { type: 'word', words: ['SECRET_PANEL'] }] }],
  };
  const hit: any = async () => new Response('...SECRET_PANEL...', { status: 200, headers: { 'content-type': 'text/plain' } });
  const miss: any = async () => new Response('<!doctype html>', { status: 200, headers: { 'content-type': 'text/html' } });
  const f = await runTemplate(tpl, 'https://app.test', hit);
  assert.ok(f && f.title === 'Test Panel' && f.severity === 'high');
  assert.equal(await runTemplate(tpl, 'https://app.test', miss), null);
});

test('runTemplates aggregates across the pack', async () => {
  // Respond as an exposed docker-compose for every request.
  const fetchFn: any = async (url: string) =>
    url.endsWith('/docker-compose.yml')
      ? new Response('version: "3"\nservices:\n web:\n  image: nginx', { status: 200, headers: { 'content-type': 'text/yaml' } })
      : new Response('not found', { status: 404, headers: { 'content-type': 'text/plain' } });
  const findings = await runTemplates('https://app.test', fetchFn, TEMPLATES);
  assert.ok(findings.some((f) => /docker-compose/i.test(f.title)));
});

test('backup-archive template fires on a zip content-type, not on an HTML page', async () => {
  const tpl = TEMPLATES.find((t) => t.id === 'backup-archive-exposed')!;
  const zip: any = async () => new Response('PK\x03\x04', { status: 200, headers: { 'content-type': 'application/zip' } });
  const html: any = async () => new Response('<!doctype html>', { status: 200, headers: { 'content-type': 'text/html' } });
  assert.ok(await runTemplate(tpl, 'https://app.test', zip));
  assert.equal(await runTemplate(tpl, 'https://app.test', html), null);
});

test('htpasswd template regex matches a hashed credential line', async () => {
  const tpl = TEMPLATES.find((t) => t.id === 'htpasswd-exposed')!;
  const hit: any = async () => new Response('admin:$apr1$xyz$abcdef', { status: 200, headers: { 'content-type': 'text/plain' } });
  const miss: any = async () => new Response('just some text', { status: 200, headers: { 'content-type': 'text/plain' } });
  assert.ok(await runTemplate(tpl, 'https://app.test', hit));
  assert.equal(await runTemplate(tpl, 'https://app.test', miss), null);
});

test('wp user-enumeration requires both slug and name (and condition)', async () => {
  const tpl = TEMPLATES.find((t) => t.id === 'wp-user-enumeration')!;
  const users: any = async () => new Response('[{"id":1,"name":"Admin","slug":"admin"}]', { status: 200, headers: { 'content-type': 'application/json' } });
  const partial: any = async () => new Response('{"slug":"x"}', { status: 200, headers: { 'content-type': 'application/json' } });
  assert.ok(await runTemplate(tpl, 'https://app.test', users));
  assert.equal(await runTemplate(tpl, 'https://app.test', partial), null);
});

test('subdomain-takeover fires on a service fingerprint at root', async () => {
  const tpl = TEMPLATES.find((t) => t.id === 'subdomain-takeover')!;
  const dangling: any = async () => new Response("There isn't a GitHub Pages site here.", { status: 404, headers: { 'content-type': 'text/html' } });
  const normal: any = async () => new Response('<!doctype html><html>Welcome</html>', { status: 200, headers: { 'content-type': 'text/html' } });
  assert.ok(await runTemplate(tpl, 'https://sub.app.test', dangling));
  assert.equal(await runTemplate(tpl, 'https://sub.app.test', normal), null);
});

test('netrc template regex matches machine login/password', async () => {
  const tpl = TEMPLATES.find((t) => t.id === 'netrc-exposed')!;
  const hit: any = async () => new Response('machine api.example.com login bob password s3cret', { status: 200, headers: { 'content-type': 'text/plain' } });
  const miss: any = async () => new Response('nothing to see', { status: 200, headers: { 'content-type': 'text/plain' } });
  assert.ok(await runTemplate(tpl, 'https://app.test', hit));
  assert.equal(await runTemplate(tpl, 'https://app.test', miss), null);
});

test('shipped templates are well-formed', () => {
  const cats = new Set(['DAST', 'SAST', 'IAST', 'SCA', 'EASM', 'RED_TEAM']);
  const ids = new Set<string>();
  for (const t of TEMPLATES) {
    assert.ok(t.id && !ids.has(t.id), `unique id: ${t.id}`);
    ids.add(t.id);
    assert.ok(t.name && t.description && t.fix);
    assert.ok(cats.has(t.category), `valid category: ${t.category}`);
    assert.ok(t.requests.length > 0 && t.requests.every((r) => r.path && r.matchers.length > 0));
  }
});
