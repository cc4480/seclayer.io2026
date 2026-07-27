import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SEVERITY_TOKENS, SECURE_TOKEN, SEVERITY_ORDER, tokenForRiskLabel, GRADE_ACCENT } from './severity.js';
import type { Severity } from '../types.js';

test('every severity has a complete visual token', () => {
  const sevs: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  for (const s of sevs) {
    const t = SEVERITY_TOKENS[s];
    assert.ok(t, `token for ${s}`);
    for (const key of ['label', 'text', 'border', 'bg', 'chip', 'hex'] as const) {
      assert.ok(t[key] && t[key].length > 0, `${s}.${key} is set`);
    }
    assert.match(t.hex, /^#[0-9a-f]{6}$/i, `${s}.hex is a hex colour`);
  }
});

test('SEVERITY_ORDER is worst-first and covers every severity exactly once', () => {
  assert.deepEqual(SEVERITY_ORDER, ['critical', 'high', 'medium', 'low', 'info']);
  assert.equal(new Set(SEVERITY_ORDER).size, SEVERITY_ORDER.length);
});

test('tokenForRiskLabel maps each risk label to the matching severity token, SECURE to the green token', () => {
  assert.equal(tokenForRiskLabel('CRITICAL'), SEVERITY_TOKENS.critical);
  assert.equal(tokenForRiskLabel('HIGH RISK'), SEVERITY_TOKENS.high);
  assert.equal(tokenForRiskLabel('MODERATE'), SEVERITY_TOKENS.medium);
  assert.equal(tokenForRiskLabel('LOW RISK'), SEVERITY_TOKENS.low);
  assert.equal(tokenForRiskLabel('INFO'), SEVERITY_TOKENS.info);
  assert.equal(tokenForRiskLabel('SECURE'), SECURE_TOKEN);
});

test('every grade band has an accent colour and label', () => {
  for (const g of ['A', 'B', 'C', 'D', 'F'] as const) {
    assert.match(GRADE_ACCENT[g].hex, /^#[0-9a-f]{6}$/i);
    assert.ok(GRADE_ACCENT[g].label.length > 0);
    assert.ok(GRADE_ACCENT[g].text.length > 0);
  }
});
