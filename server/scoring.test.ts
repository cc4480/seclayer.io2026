import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  scoreFindings, SEVERITY_WEIGHTS, SCORE_FLOOR,
  deriveSecurityPosture, riskLabelForSeverity, bannerForPosture,
} from './scoring.js';

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

test('info findings carry a small weight so any finding dents the score', () => {
  const r = scoreFindings([{ severity: 'info' } as any, { severity: 'info' } as any]);
  // A scan with N>0 findings must never present as a flawless 100/100.
  assert.equal(r.score, 100 - 2 * SEVERITY_WEIGHTS.info);
  assert.ok(r.score < 100);
  assert.equal(r.severity, 'info');
});

test('posture: score, grade, posture rating and counts agree for the same findings', () => {
  const p = deriveSecurityPosture([
    { severity: 'medium', confidence: 'medium' } as any,
    { severity: 'low', confidence: 'high' } as any,
  ]);
  assert.equal(p.score, 100 - SEVERITY_WEIGHTS.medium - SEVERITY_WEIGHTS.low); // 80
  assert.equal(p.severity, 'medium');
  assert.equal(p.postureRating, 'MODERATE');
  assert.equal(p.grade, 'B');
  assert.equal(p.activeCount, 2);
  assert.equal(p.findingsBySeverity.medium, 1);
  assert.equal(p.findingsBySeverity.low, 1);
});

test('posture: confirmed vs needs-verification split follows confidence', () => {
  const p = deriveSecurityPosture([
    { severity: 'high', confidence: 'high' } as any,   // confirmed
    { severity: 'medium', confidence: 'medium' } as any, // needs verification
    { severity: 'low', confidence: 'low' } as any,       // needs verification
  ]);
  assert.equal(p.confirmedCount, 1);
  assert.equal(p.needsVerificationCount, 2);
});

test('riskLabelForSeverity never labels an info/low posture as MODERATE or worse', () => {
  assert.equal(riskLabelForSeverity(null), 'SECURE');
  assert.equal(riskLabelForSeverity('info'), 'INFO');
  assert.equal(riskLabelForSeverity('low'), 'LOW RISK');
  assert.equal(riskLabelForSeverity('medium'), 'MODERATE');
  assert.equal(riskLabelForSeverity('critical'), 'CRITICAL');
});

test('banner: no red alarm for an info/low worst case, derived from real severity', () => {
  assert.equal(bannerForPosture([]), null);

  const infoBanner = bannerForPosture([{ severity: 'info', title: 'Server header leaks version' } as any]);
  assert.equal(infoBanner?.level, 'notice'); // not "critical" — no red fix-immediately alarm

  const lowBanner = bannerForPosture([{ severity: 'low', title: 'Cookie missing SameSite' } as any]);
  assert.equal(lowBanner?.level, 'notice');
});

test('banner: alarming language is gated behind genuine high/critical severity', () => {
  const medium = bannerForPosture([{ severity: 'medium', title: 'Missing CSP' } as any]);
  assert.equal(medium?.level, 'warning');

  const critical = bannerForPosture([{ severity: 'critical', title: 'SQL injection' } as any]);
  assert.equal(critical?.level, 'critical');
  assert.match(critical!.message, /SQL injection/); // text derived from the actual worst finding
});
