import { test } from 'node:test';
import assert from 'node:assert/strict';
import { shouldNotify, buildScanNotification, detectRegression } from './notify.js';
import type { Scan, Finding } from '../src/types.js';

const scan = (over: Partial<Scan>): Scan => ({
  id: 's1', userId: 'u1', url: 'https://acme.test', status: 'complete',
  createdAt: '', ...over,
});

const finding = (over: Partial<Finding>): Finding => ({
  id: 'f' + Math.random(), title: 't', description: '', severity: 'high', fix: '', category: 'DAST', ...over,
});

test('shouldNotify only fires on complete scans with active high/critical', () => {
  assert.equal(shouldNotify(scan({ status: 'scanning', findings: [{ id: 'a', title: 'x', description: '', severity: 'critical', fix: '', category: 'DAST' }] })), false);
  assert.equal(shouldNotify(scan({ findings: [{ id: 'a', title: 'x', description: '', severity: 'low', fix: '', category: 'DAST' }] })), false);
  assert.equal(shouldNotify(scan({ findings: [{ id: 'a', title: 'x', description: '', severity: 'high', fix: '', category: 'DAST' }] })), true);
});

test('suppressed findings do not trigger a notification', () => {
  assert.equal(
    shouldNotify(scan({ findings: [{ id: 'a', title: 'x', description: '', severity: 'critical', fix: '', category: 'DAST', isFalsePositive: true }] })),
    false,
  );
});

test('buildScanNotification summarizes counts and includes scan context', () => {
  const n = buildScanNotification(scan({
    score: 30, severity: 'critical',
    findings: [
      { id: 'a', title: 'x', description: '', severity: 'critical', fix: '', category: 'DAST' },
      { id: 'b', title: 'y', description: '', severity: 'high', fix: '', category: 'DAST' },
      { id: 'c', title: 'z', description: '', severity: 'high', fix: '', category: 'DAST', isFalsePositive: true },
    ],
  }));
  assert.equal(n.critical, 1);
  assert.equal(n.high, 1); // suppressed high excluded
  assert.equal(n.scanId, 's1');
  assert.match(n.text, /acme\.test/);
  assert.match(n.text, /1 critical, 1 high/);
});

test('regression: first scan with high/critical alerts as a baseline', () => {
  const r = detectRegression(scan({ score: 40, findings: [finding({ title: 'SQLi', severity: 'critical' })] }), undefined);
  assert.equal(r.shouldAlert, true);
  assert.equal(r.isBaseline, true);
  assert.equal(r.newFindings.length, 1);
  assert.match(buildScanNotification(scan({ score: 40 }), r).text, /baseline/i);
});

test('regression: first scan with no high/critical does not alert', () => {
  const r = detectRegression(scan({ score: 95, findings: [finding({ severity: 'low' })] }), undefined);
  assert.equal(r.shouldAlert, false);
  assert.equal(r.isBaseline, true);
});

test('regression: a re-scan with the same findings and score is silent', () => {
  const findings = [finding({ title: 'Open .env', severity: 'high', category: 'DAST' })];
  const prev = scan({ id: 'p', score: 70, findings });
  const cur = scan({ id: 'c', score: 70, findings: [finding({ title: 'Open .env', severity: 'high', category: 'DAST' })] });
  assert.equal(detectRegression(cur, prev).shouldAlert, false);
});

test('regression: a brand-new high/critical finding alerts', () => {
  const prev = scan({ id: 'p', score: 70, findings: [finding({ title: 'Open .env', severity: 'high' })] });
  const cur = scan({
    id: 'c', score: 70,
    findings: [finding({ title: 'Open .env', severity: 'high' }), finding({ title: 'SQL Injection', severity: 'critical' })],
  });
  const r = detectRegression(cur, prev);
  assert.equal(r.shouldAlert, true);
  assert.equal(r.isBaseline, false);
  assert.equal(r.newFindings.length, 1);
  assert.equal(r.newFindings[0].title, 'SQL Injection');
  assert.match(buildScanNotification(cur, r).text, /regression/i);
});

test('regression: a dropped posture score alerts even with no new findings', () => {
  const findings = [finding({ title: 'Open .env', severity: 'high' })];
  const prev = scan({ id: 'p', score: 80, findings });
  const cur = scan({ id: 'c', score: 55, findings: [finding({ title: 'Open .env', severity: 'high' })] });
  const r = detectRegression(cur, prev);
  assert.equal(r.shouldAlert, true);
  assert.equal(r.newFindings.length, 0);
  assert.match(r.reason, /80→55/);
});

test('regression: a suppressed new finding is not treated as a regression', () => {
  const prev = scan({ id: 'p', score: 70, findings: [finding({ title: 'Open .env', severity: 'high' })] });
  const cur = scan({
    id: 'c', score: 70,
    findings: [finding({ title: 'Open .env', severity: 'high' }), finding({ title: 'SQLi', severity: 'critical', isFalsePositive: true })],
  });
  assert.equal(detectRegression(cur, prev).shouldAlert, false);
});
