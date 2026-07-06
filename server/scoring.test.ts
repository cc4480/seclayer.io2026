import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scoreFindings, SEVERITY_WEIGHTS, SCORE_FLOOR } from './scoring.js';

test('no findings yields a perfect, info-level score', () => {
  const r = scoreFindings([]);
  assert.equal(r.score, 100);
  assert.equal(r.severity, 'info');
});

test('a single critical deducts its weight and sets severity', () => {
  const r = scoreFindings([{ severity: 'critical' } as any]);
  assert.equal(r.score, 100 - SEVERITY_WEIGHTS.critical);
  assert.equal(r.severity, 'critical');
});

test('suppressed (false-positive) findings are excluded from score and severity', () => {
  const r = scoreFindings([
    { severity: 'critical', isFalsePositive: true } as any,
    { severity: 'low' } as any,
  ]);
  assert.equal(r.score, 95);
  assert.equal(r.severity, 'low');
});

test('score never drops below the floor', () => {
  const many = Array.from({ length: 20 }, () => ({ severity: 'critical' } as any));
  assert.equal(scoreFindings(many).score, SCORE_FLOOR);
});

test('info findings carry zero weight', () => {
  const r = scoreFindings([{ severity: 'info' } as any, { severity: 'info' } as any]);
  assert.equal(r.score, 100);
  assert.equal(r.severity, 'info');
});
