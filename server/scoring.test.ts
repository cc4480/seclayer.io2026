import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  scoreFindings, SEVERITY_WEIGHTS, SCORE_FLOOR,
  deriveSecurityPosture, riskLabelForSeverity, bannerForPosture,
  isProven, isConfirmed,
} from './scoring.js';

function evidence(response: string, quote: string): any {
  return {
    method: 'reflection',
    attack: { request: 'GET /?q=… HTTP/1.1', response },
    signal: { quote, offsetInResponse: response.indexOf(quote), why: 'reflected' },
    demonstration: 'demo', reproduction: 'curl …', capturedAt: '',
  };
}

test('isProven requires the quoted proof to actually appear in the stored response', () => {
  // Valid receipt: the quote is a literal substring of the captured response.
  assert.equal(isProven({ evidence: evidence('x<script>abc</script>y', '<script>abc</script>') } as any), true);
  // Invalid: we claim a proof the stored response does not contain → never PROVEN.
  assert.equal(isProven({ evidence: evidence('nothing to see here', '<script>abc</script>') } as any), false);
  // No bundle at all.
  assert.equal(isProven({} as any), false);
  assert.equal(isProven({ evidence: { attack: { response: 'x' }, signal: { quote: '' } } } as any), false);
});

test('adding PROVEN never demotes a legacy high-confidence finding (additive)', () => {
  // A finding with no evidence bundle but high confidence stays Confirmed.
  assert.equal(isConfirmed({ confidence: 'high' } as any), true);
  assert.equal(isConfirmed({ confidence: undefined } as any), true);
  // A valid receipt is Confirmed too (via PROVEN), regardless of confidence.
  assert.equal(isConfirmed({ confidence: 'low', evidence: evidence('a<b>c', '<b>') } as any), true);
  // A low-confidence heuristic with no receipt stays in the lower tier.
  assert.equal(isConfirmed({ confidence: 'low' } as any), false);
});

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

test('info findings never affect the score — only critical/high/medium/low do', () => {
  // Info notices are scan context (surface mapped, probing skipped), not
  // weaknesses, so a site whose only findings are informational scores a true 100.
  const r = scoreFindings([{ severity: 'info' } as any, { severity: 'info' } as any, { severity: 'info' } as any]);
  assert.equal(SEVERITY_WEIGHTS.info, 0);
  assert.equal(r.score, 100);
  assert.equal(r.severity, 'info');
});

test('info findings alongside a real finding contribute nothing extra to the deduction', () => {
  const withInfo = scoreFindings([{ severity: 'medium' } as any, { severity: 'info' } as any, { severity: 'info' } as any]);
  const withoutInfo = scoreFindings([{ severity: 'medium' } as any]);
  assert.equal(withInfo.score, withoutInfo.score, 'info notices must not change the score');
  assert.equal(withInfo.score, 100 - SEVERITY_WEIGHTS.medium);
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
