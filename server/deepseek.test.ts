import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateAiReport, refineCategory, reattachEvidence, mergeModelProse } from './deepseek.js';
import type { Finding, ExploitEvidence } from '../src/types.js';

const receipt = (quote: string): ExploitEvidence => ({
  method: 'reflection',
  attack: { request: 'GET /?q=… HTTP/1.1', response: `…${quote}…` },
  signal: { quote, offsetInResponse: 1, why: 'reflected' },
  demonstration: 'demo', reproduction: 'curl …', capturedAt: '',
});

test('reattachEvidence replaces the AI\'s reworded exploit finding with the PROVEN original (no duplicate)', () => {
  // The model reworded the machine finding and dropped its receipt.
  const aiFindings: Finding[] = [
    { id: 'ai1', title: 'SQL Injection', description: 'd', severity: 'high', fix: 'f', category: 'RED_TEAM' },
    { id: 'ai2', title: 'Missing CSP', description: 'd', severity: 'medium', fix: 'f', category: 'IAST' },
  ];
  const compiled: Finding[] = [
    { id: 'rt1', title: 'Active SQL Injection Probe', description: 'd', severity: 'critical', fix: 'f', category: 'RED_TEAM', evidence: receipt("SQL syntax;") },
  ];
  const out = reattachEvidence(aiFindings, compiled);
  const sqli = out.filter((f) => /sql/i.test(f.title));
  assert.equal(sqli.length, 1, 'exactly one SQLi finding — no evidence-less duplicate');
  assert.equal(sqli[0].title, 'Active SQL Injection Probe', 'the machine finding wins');
  assert.ok(sqli[0].evidence, 'and it keeps its receipt');
  assert.equal(sqli[0].severity, 'critical');
  // Non-exploit AI findings are preserved.
  assert.ok(out.some((f) => f.title === 'Missing CSP'));
});

test('reattachEvidence splices in an evidence-backed exploit the AI omitted entirely', () => {
  const aiFindings: Finding[] = [
    { id: 'ai1', title: 'Missing CSP', description: 'd', severity: 'medium', fix: 'f', category: 'IAST' },
  ];
  const compiled: Finding[] = [
    { id: 'api1', title: 'Broken Object Level Authorization (BOLA)', description: 'd', severity: 'critical', fix: 'f', category: 'API_SEC', evidence: receipt('bob@example.test') },
  ];
  const out = reattachEvidence(aiFindings, compiled);
  const bola = out.find((f) => /BOLA/i.test(f.title));
  assert.ok(bola && bola.evidence, 'a PROVEN exploit must always be present with its receipt');
  assert.equal(out.length, 2);
});

test('reattachEvidence leaves non-exploit findings to the AI', () => {
  const aiFindings: Finding[] = [
    { id: 'ai1', title: 'Missing CSP', description: 'ai wording', severity: 'medium', fix: 'f', category: 'IAST' },
  ];
  const compiled: Finding[] = [
    { id: 'c1', title: 'Missing Content-Security-Policy (CSP)', description: 'machine', severity: 'medium', fix: 'f', category: 'IAST' },
  ];
  const out = reattachEvidence(aiFindings, compiled);
  assert.equal(out.length, 1, 'IAST is the AI\'s pillar — machine copy is not force-added');
  assert.equal(out[0].description, 'ai wording');
});

test('refineCategory corrects the model\'s lazy DAST bucketing by title', () => {
  // Headers / cookies / session policy → IAST
  assert.equal(refineCategory('DAST', 'Missing Content-Security-Policy (CSP)'), 'IAST');
  assert.equal(refineCategory('DAST', 'Missing Strict-Transport-Security (HSTS) Policy'), 'IAST');
  assert.equal(refineCategory('DAST', 'Cookie Set Without HttpOnly Attribute'), 'IAST');
  // Perimeter / server disclosure → EASM
  assert.equal(refineCategory('DAST', 'Verbose Server Framework Signature Leak'), 'EASM');
  assert.equal(refineCategory('DAST', 'Insecure Connection Protocol (HTTP)'), 'EASM');
  // Dependencies → SCA
  assert.equal(refineCategory('DAST', 'Outdated Library Vulnerability Detected (jQuery)'), 'SCA');
  // Genuinely dynamic findings keep the model's category
  assert.equal(refineCategory('DAST', 'Application Surface Mapped'), 'DAST');
  assert.equal(refineCategory('RED_TEAM', 'Active SQL Injection Probe'), 'RED_TEAM');
});

// The test runner never loads .env.local, so DEEPSEEK_API_KEY is unset here
// and generateAiReport exercises its local, deterministic fallback path — the
// same one used in production when no key is configured.

test('generateAiReport always returns a populated executiveBreakdown, even without DeepSeek', async () => {
  const findings: Finding[] = [
    { id: 'a', title: 'Missing CSP', description: 'desc', severity: 'high', fix: 'Add a CSP header.', category: 'IAST' },
    { id: 'b', title: 'Outdated jQuery', description: 'desc', severity: 'medium', fix: 'Upgrade jQuery.', category: 'SCA' },
  ];
  const staticCompiled = { score: 55, severity: 'high' as const, findings };

  const report = await generateAiReport('https://x.test', { techLeaked: [], missingHeaders: [], sslSecure: true, responseStatus: 200, probedPaths: [], cookieIssues: [] }, staticCompiled);

  assert.ok(report.executiveBreakdown);
  assert.match(report.executiveBreakdown.overview, /x\.test/);
  assert.ok(report.executiveBreakdown.riskAreas.length > 0);
  assert.ok(report.executiveBreakdown.businessImpact.length > 0);
  assert.ok(report.executiveBreakdown.priorityActions.length > 0);
  // Highest-severity finding's fix should be prioritized first.
  assert.equal(report.executiveBreakdown.priorityActions[0], 'Add a CSP header.');
});

test('generateAiReport reports clean hygiene and no risk areas placeholder for zero findings', async () => {
  const staticCompiled = { score: 100, severity: 'info' as const, findings: [] as Finding[] };
  const report = await generateAiReport('https://clean.test', { techLeaked: [], missingHeaders: [], sslSecure: true, responseStatus: 200, probedPaths: [], cookieIssues: [] }, staticCompiled);

  assert.equal(report.executiveBreakdown.riskAreas[0].area, 'General Hygiene');
  assert.equal(report.executiveBreakdown.priorityActions[0], 'No action required — no active findings this scan.');
});

// --- mergeModelProse -------------------------------------------------------
// The model is asked for a per-finding `agentPrompt` (server/reportPrompt.ts).
// It used to be discarded wholesale with the rest of the model's findings array,
// so every report shipped the generic static fallback prompt instead.

const staticF = (id: string, title: string): Finding => ({
  id, title, description: 'd', severity: 'medium', fix: 'f', category: 'DAST',
  agentPrompt: `STATIC PROMPT for ${title}`, impact: 'static impact',
});

test('mergeModelProse puts the model-authored fix prompt on the matching static finding', () => {
  const compiled = [staticF('a', 'Missing CSP header')];
  const merged = mergeModelProse(compiled, [
    { title: 'Content-Security-Policy absent', sourceTitles: ['Missing CSP header'],
      agentPrompt: 'MODEL PROMPT', impact: 'model impact' },
  ]);

  assert.equal(merged[0].agentPrompt, 'MODEL PROMPT');
  assert.equal(merged[0].impact, 'model impact');
});

test('mergeModelProse matches sourceTitles ignoring case and surrounding whitespace', () => {
  const merged = mergeModelProse([staticF('a', 'Missing CSP header')], [
    { sourceTitles: ['  missing csp HEADER '], agentPrompt: 'MODEL PROMPT' },
  ]);
  assert.equal(merged[0].agentPrompt, 'MODEL PROMPT');
});

test('mergeModelProse applies a consolidated finding to every issue it absorbed', () => {
  const compiled = [staticF('a', 'Missing CSP header'), staticF('b', 'Missing HSTS header')];
  const merged = mergeModelProse(compiled, [
    { sourceTitles: ['Missing CSP header', 'Missing HSTS header'], agentPrompt: 'HEADERS PROMPT' },
  ]);

  assert.equal(merged[0].agentPrompt, 'HEADERS PROMPT');
  assert.equal(merged[1].agentPrompt, 'HEADERS PROMPT');
});

test('mergeModelProse keeps the static fallback when the model cites a title that does not exist', () => {
  const merged = mergeModelProse([staticF('a', 'Missing CSP header')], [
    { sourceTitles: ['Some finding the scanner never reported'], agentPrompt: 'MODEL PROMPT' },
  ]);
  assert.equal(merged[0].agentPrompt, 'STATIC PROMPT for Missing CSP header');
});

test('mergeModelProse never lets the model change identity, severity or the finding count', () => {
  const compiled = [staticF('a', 'Missing CSP header')];
  const merged = mergeModelProse(compiled, [
    // Reworded title, escalated severity, and an entirely invented extra finding.
    { title: 'CRITICAL: total compromise', severity: 'critical', category: 'RED_TEAM',
      sourceTitles: ['Missing CSP header'], agentPrompt: 'MODEL PROMPT' },
    { title: 'Invented finding', severity: 'critical', sourceTitles: [], agentPrompt: 'NOPE' },
  ]);

  assert.equal(merged.length, 1);
  assert.equal(merged[0].title, 'Missing CSP header');
  assert.equal(merged[0].severity, 'medium');
  assert.equal(merged[0].category, 'DAST');
  assert.equal(merged[0].agentPrompt, 'MODEL PROMPT');
});

test('mergeModelProse tolerates malformed model output and never mutates the compiled findings', () => {
  const compiled = [staticF('a', 'Missing CSP header')];

  for (const bad of [undefined, null, 'not an array', [null], [{ sourceTitles: 'x' }], [{ sourceTitles: [7] }], [{ sourceTitles: ['Missing CSP header'], agentPrompt: '   ' }]]) {
    const merged = mergeModelProse(compiled, bad as unknown);
    assert.equal(merged[0].agentPrompt, 'STATIC PROMPT for Missing CSP header');
  }
  assert.equal(compiled[0].agentPrompt, 'STATIC PROMPT for Missing CSP header');
});

test('mergeModelProse rewrites the prose the UI Complete Fix Prompt is built from', () => {
  // src/lib/scanFixPrompt.ts composes its prompt from description/impact/fix,
  // not agentPrompt, so those have to be merged for the UI hand-off to improve.
  const merged = mergeModelProse([staticF('a', 'Missing CSP header')], [
    { sourceTitles: ['Missing CSP header'],
      description: 'model description', fix: 'model fix', impact: 'model impact' },
  ]);

  assert.equal(merged[0].description, 'model description');
  assert.equal(merged[0].fix, 'model fix');
  assert.equal(merged[0].impact, 'model impact');
});

test('mergeModelProse never reworders a receipt-backed exploit finding', () => {
  // Same invariant reattachEvidence enforces: a PROVEN exploit is the scanner's,
  // not the model's, however confidently the model rewrites it.
  const exploit: Finding = {
    id: 'x', title: 'Active SQL Injection Probe', description: 'scanner description',
    severity: 'critical', fix: 'scanner fix', category: 'RED_TEAM',
    agentPrompt: 'SCANNER PROMPT', impact: 'scanner impact', evidence: receipt('SQL syntax;'),
  };
  const merged = mergeModelProse([exploit], [
    { sourceTitles: ['Active SQL Injection Probe'], description: 'softened',
      fix: 'model fix', impact: 'model impact', agentPrompt: 'MODEL PROMPT' },
  ]);

  assert.equal(merged[0].description, 'scanner description');
  assert.equal(merged[0].fix, 'scanner fix');
  assert.equal(merged[0].impact, 'scanner impact');
  assert.equal(merged[0].agentPrompt, 'SCANNER PROMPT');
});
