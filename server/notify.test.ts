import { test } from 'node:test';
import assert from 'node:assert/strict';
import { shouldNotify, buildScanNotification } from './notify.js';
import type { Scan } from '../src/types.js';

const scan = (over: Partial<Scan>): Scan => ({
  id: 's1', userId: 'u1', url: 'https://acme.test', status: 'complete',
  createdAt: '', ...over,
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
