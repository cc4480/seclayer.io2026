import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectTechTags } from './techprofile.js';
import { selectTemplates, Template } from './templateEngine.js';

test('WordPress markup implies wordpress + php', () => {
  const tags = detectTechTags({}, '<link href="/wp-content/themes/x/style.css">');
  assert.ok(tags.has('wordpress'));
  assert.ok(tags.has('php'));
});

test('Spring header implies spring + java', () => {
  const tags = detectTechTags({ 'x-application-context': 'application:prod' }, '');
  assert.ok(tags.has('spring'));
  assert.ok(tags.has('java'));
});

test('Express header implies node, JSESSIONID implies java', () => {
  assert.ok(detectTechTags({ 'x-powered-by': 'Express' }, '').has('node'));
  assert.ok(detectTechTags({ 'set-cookie': 'JSESSIONID=abc; Path=/' }, '').has('java'));
});

test('a plain static site detects no framework tags', () => {
  const tags = detectTechTags({ server: 'nginx' }, '<!doctype html><html><body>hi</body></html>');
  assert.equal(tags.size, 0);
});

test('selectTemplates runs generic always and tagged only when detected', () => {
  const tpls: Template[] = [
    { id: 'generic', name: 'g', severity: 'low', category: 'DAST', description: '', fix: '', requests: [] },
    { id: 'wp', name: 'w', severity: 'low', category: 'DAST', description: '', fix: '', requests: [], tags: ['wordpress'] },
    { id: 'spring', name: 's', severity: 'low', category: 'DAST', description: '', fix: '', requests: [], tags: ['spring'] },
  ];
  const sel = selectTemplates(tpls, new Set(['wordpress', 'php']));
  const ids = sel.map((t) => t.id);
  assert.ok(ids.includes('generic'));
  assert.ok(ids.includes('wp'));
  assert.ok(!ids.includes('spring'));
});

test('with no detected tech, only generic templates run', () => {
  const tpls: Template[] = [
    { id: 'generic', name: 'g', severity: 'low', category: 'DAST', description: '', fix: '', requests: [] },
    { id: 'wp', name: 'w', severity: 'low', category: 'DAST', description: '', fix: '', requests: [], tags: ['wordpress'] },
  ];
  assert.deepEqual(selectTemplates(tpls, new Set()).map((t) => t.id), ['generic']);
});
