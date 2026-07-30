import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildScanCoverage } from './coverage.js';
import { SECURITY_HEADERS } from './passiveScan.js';
import { SECRET_SIGNATURE_COUNT, LIBRARY_SIGNATURE_COUNT } from './staticAnalysis.js';
import { RED_TEAM_PROBE_COUNT } from './redTeamProbes.js';
import { AGGRESSIVE_PROBE_COUNT } from './aggressiveProbes.js';
import { API_PROBE_COUNT } from './apiProbes.js';

const passiveInputs = {
  activeProbesRun: false, aggressiveProbesRun: false,
  subdomainsChecked: 33, pathsProbed: 6, templatesRun: 12, crawlPages: 8, paramsFuzzed: 0, domXssRun: false,
};

test('passive coverage totals only the groups that ran, and gates the exploit tiers', () => {
  const c = buildScanCoverage(passiveInputs);
  // Sum of passive checks: headers + cookie(2) + tls(1) + dns(2) + subs(33) + secrets + libs + paths(6) + templates(12) + crawl(8).
  const expected = SECURITY_HEADERS.length + 2 + 1 + 2 + 33 + SECRET_SIGNATURE_COUNT + LIBRARY_SIGNATURE_COUNT + 6 + 12 + 8;
  assert.equal(c.totalChecks, expected);
  assert.equal(c.activeProbesRun, false);
  // Every RED_TEAM/API_SEC exploit group is present but not run, each with a reason.
  const gated = c.items.filter((i) => !i.ran);
  assert.ok(gated.length >= 5, 'exploit + aggressive groups are listed as gated');
  assert.ok(gated.every((i) => typeof i.note === 'string' && i.note.length > 0), 'every gated group explains why');
});

test('active scan runs the exploit probes and counts them', () => {
  const c = buildScanCoverage({ ...passiveInputs, activeProbesRun: true, paramsFuzzed: 14 });
  const redTeam = c.items.find((i) => i.label.startsWith('Red-team exploit probes'));
  assert.equal(redTeam!.ran, true);
  assert.equal(redTeam!.checks, RED_TEAM_PROBE_COUNT);
  const api = c.items.find((i) => i.category === 'API_SEC');
  assert.equal(api!.ran, true);
  assert.equal(api!.checks, API_PROBE_COUNT);
  // Active total = passive total + red-team(5) + params(14) + api(3) + jwt(1). DOM off.
  const passive = buildScanCoverage(passiveInputs).totalChecks;
  assert.equal(c.totalChecks, passive + RED_TEAM_PROBE_COUNT + 14 + API_PROBE_COUNT + 1);
});

test('aggressive opt-in adds the invasive tier to the count', () => {
  const withAgg = buildScanCoverage({ ...passiveInputs, activeProbesRun: true, aggressiveProbesRun: true, paramsFuzzed: 0 });
  const withoutAgg = buildScanCoverage({ ...passiveInputs, activeProbesRun: true, aggressiveProbesRun: false, paramsFuzzed: 0 });
  // Aggressive adds the 8-probe tier + stored-XSS(1).
  assert.equal(withAgg.totalChecks, withoutAgg.totalChecks + AGGRESSIVE_PROBE_COUNT + 1);
  assert.equal(withAgg.aggressiveProbesRun, true);
});

test('a group with zero discrete checks (e.g. no templates matched) is marked not-run', () => {
  const c = buildScanCoverage({ ...passiveInputs, templatesRun: 0, crawlPages: 0 });
  assert.equal(c.items.find((i) => i.label.startsWith('Template'))!.ran, false);
  assert.equal(c.items.find((i) => i.label.startsWith('Crawl'))!.ran, false);
});
