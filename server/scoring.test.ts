import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  scoreFindings, SEVERITY_WEIGHTS, SCORE_FLOOR,
  deriveSecurityPosture, riskLabelForSeverity, bannerForPosture,
  isProven, isConfirmed, HEURISTIC_CONFIDENCE_FACTOR, HEURISTIC_DEDUCTION_CAP,
  CONFIRMED_SEVERITY_CEILING, gradeForScore, resultTier, resultMarker,
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

test('a single CONFIRMED critical fails the grade — severity dominates count', () => {
  // A proven/high-confidence critical (e.g. exposed .env, leaked live key) must
  // be an F even as the only finding, not a middling "D" from one -35 deduction.
  const r = scoreFindings([{ severity: 'critical' } as any]);
  assert.equal(r.score, CONFIRMED_SEVERITY_CEILING.critical);
  assert.equal(gradeForScore(r.score), 'F');
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
    { severity: 'medium', confidence: 'medium' } as any, // unconfirmed → damped to half
    { severity: 'low', confidence: 'high' } as any,      // confirmed → full weight
  ]);
  // Evidence-weighted: 100 − low(5) − medium(15)*0.5 = 87.5 → 88.
  assert.equal(p.score, 88);
  assert.equal(p.severity, 'medium');
  assert.equal(p.postureRating, 'MODERATE');
  assert.equal(p.grade, 'B');
  assert.equal(p.activeCount, 2);
  assert.equal(p.findingsBySeverity.medium, 1);
  assert.equal(p.findingsBySeverity.low, 1);
});

test('a confirmed finding deducts its FULL weight — a real vulnerability always moves the grade', () => {
  // A confirmed critical is ceilinged to an F (severity dominates); a confirmed
  // medium has no ceiling and deducts its full weight (never damped like a heuristic).
  assert.equal(deriveSecurityPosture([{ severity: 'critical', confidence: 'high' } as any]).score, CONFIRMED_SEVERITY_CEILING.critical);
  const proven = deriveSecurityPosture([{ severity: 'medium', confidence: 'low', evidence: evidence('a<b>c', '<b>') } as any]);
  assert.equal(proven.score, 100 - SEVERITY_WEIGHTS.medium, 'a PROVEN finding is never damped by its confidence label');
});

test('an UNCONFIRMED high does NOT trigger the severity ceiling (no false-positive auto-fail)', () => {
  // A library-version match or an unverified key id is high-severity but medium
  // confidence — it must NOT auto-fail the site the way a confirmed high does.
  const p = deriveSecurityPosture([{ severity: 'high', confidence: 'medium' } as any]);
  assert.ok(p.score > CONFIRMED_SEVERITY_CEILING.high!, `unconfirmed high must not hit the ceiling, got ${p.score}`);
  // A CONFIRMED high, by contrast, fails.
  const confirmed = deriveSecurityPosture([{ severity: 'high', confidence: 'high' } as any]);
  assert.equal(confirmed.score, CONFIRMED_SEVERITY_CEILING.high);
  assert.equal(gradeForScore(confirmed.score), 'F');
});

test('an unconfirmed finding is damped by its confidence, not counted at full weight', () => {
  const med = deriveSecurityPosture([{ severity: 'medium', confidence: 'medium' } as any]).score;
  assert.equal(med, Math.round(100 - SEVERITY_WEIGHTS.medium * HEURISTIC_CONFIDENCE_FACTOR.medium)); // 93
  const low = deriveSecurityPosture([{ severity: 'low', confidence: 'low' } as any]).score;
  assert.equal(low, Math.round(100 - SEVERITY_WEIGHTS.low * HEURISTIC_CONFIDENCE_FACTOR.low)); // 99
});

test('a pile of UNCONFIRMED findings is capped and can never manufacture an F', () => {
  // Ten medium-confidence mediums would linearly subtract 150; damped they are
  // 75, but the heuristic cap holds the deduction at 40 → 60 (grade D), never F.
  const many = Array.from({ length: 10 }, () => ({ severity: 'medium', confidence: 'medium' } as any));
  const p = deriveSecurityPosture(many);
  assert.equal(p.score, 100 - HEURISTIC_DEDUCTION_CAP); // 60
  assert.equal(p.grade, 'D');
  assert.notEqual(p.grade, 'F');
});

test('the heuristic cap NEVER shields confirmed vulnerabilities — real findings still reach F', () => {
  const many = Array.from({ length: 3 }, () => ({ severity: 'critical', confidence: 'high' } as any));
  const p = deriveSecurityPosture(many);
  assert.equal(p.score, SCORE_FLOOR); // 3 confirmed criticals crater past the floor
  assert.equal(p.grade, 'F');
});

test('the lovable.dev shape: one heuristic medium + one confirmed low is a B, not an F', () => {
  // The exact class of report that used to score 10/100: hygiene findings, none
  // proven. With evidence weighting it lands where a well-built site belongs.
  const p = deriveSecurityPosture([
    { severity: 'medium', confidence: 'medium' } as any, // e.g. missing X-Frame-Options (black-box)
    { severity: 'low', confidence: 'high' } as any,      // e.g. a preference cookie missing Secure
  ]);
  assert.ok(p.score >= 85, `expected a healthy score, got ${p.score}`);
  assert.equal(p.grade, 'B');
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

test('an intercepted scan gets grade N/A, never a passing letter', () => {
  // A bot-protection layer answered, so compileStaticFindings withheld
  // everything content-derived and left only info-severity coverage notes.
  // That set scores near 100, and gradeForScore(100) is "A". The posture must
  // refuse to grade it — the alternative is an interstitial's silence read as
  // the site's merit.
  const withheld: any[] = [
    { title: 'Scan was intercepted by a bot-protection challenge', severity: 'info', confidence: 'high' },
    { title: 'Insecure Connection Protocol (HTTP)', severity: 'info', confidence: 'high' },
  ];
  const p = deriveSecurityPosture(withheld);
  assert.equal(p.intercepted, true);
  assert.equal(p.grade, 'N/A');
  // The score itself is high (only info survived) — which is exactly why the
  // grade must not follow it.
  assert.ok(p.score >= 90);
  assert.ok(gradeForScore(p.score) === 'A'); // the trap we are avoiding
});

test('a normal scan is unaffected — still graded by score', () => {
  const clean: any[] = [
    { title: 'Missing Referrer-Policy', severity: 'low', confidence: 'high' },
  ];
  const p = deriveSecurityPosture(clean);
  assert.equal(p.intercepted, false);
  assert.match(p.grade, /^[A-F]$/);
});

// A finding whose own title says "needs verification" must never be reported as
// CONFIRMED. It did: bola.ts emitted the inconclusive Cross-Tenant Access
// findings with no confidence, findings.ts defaults a red-team finding to
// "high", and isConfirmed() treats "high" as confirmed — so a real scan of
// seclayer.app printed "Cross-Tenant Access (needs verification) — MEDIUM
// confirmed", which is a contradiction in four words.
test('a "needs verification" finding is never confirmed', () => {
  const inconclusive: any = {
    title: 'Cross-Tenant Access (needs verification)',
    severity: 'medium',
    confidence: 'low',
  };
  assert.equal(isConfirmed(inconclusive), false);

  // And the trap that caused it: no confidence at all still reads as confirmed,
  // so any probe emitting an unprovable claim MUST declare its confidence.
  assert.equal(isConfirmed({ title: 'x', severity: 'medium' } as any), true);
});

// The posture must count it as needing verification, not as a confirmed medium.
test('an inconclusive cross-tenant finding counts as needs-verification', () => {
  const p = deriveSecurityPosture([
    { title: 'Cross-Tenant Access (needs verification)', severity: 'medium', confidence: 'low' } as any,
  ]);
  assert.equal(p.confirmedCount, 0);
  assert.equal(p.needsVerificationCount, 1);
});

test('resultTier / resultMarker label a finding by what was actually determined', () => {
  // The live feed and the report both run through this, so the contradiction
  // the user saw — "needs verification ... ✓ CONFIRMED" — cannot recur.
  const proven: any = {
    severity: 'critical',
    evidence: { attack: { response: 'X id=42 Y' }, signal: { quote: 'id=42' } },
  };
  assert.equal(resultTier(proven), 'PROVEN');
  assert.equal(resultMarker(resultTier(proven)), '✓ PROVEN');

  assert.equal(resultTier({ severity: 'high', confidence: 'high' } as any), 'CONFIRMED');

  const inconclusive: any = { severity: 'medium', confidence: 'low' };
  assert.equal(resultTier(inconclusive), 'NEEDS VERIFICATION');
  assert.equal(resultMarker(resultTier(inconclusive)), '⚠ NEEDS VERIFICATION');

  // The cross-tenant "Enforced" pass is info — a passing control, not a vuln.
  assert.equal(resultTier({ severity: 'info', confidence: 'high' } as any), 'PASS');
});
