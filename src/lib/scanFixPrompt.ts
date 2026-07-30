import { Finding, Scan, Severity } from '../types.js';
// Single source of truth for score/rating — same module the report and server use.
import { deriveSecurityPosture } from '../../server/scoring.js';

// Builds ONE complete, agent-agnostic remediation prompt for an entire scan — the
// "Complete Fix Prompt" the report hands off in a single copy. It replaces the
// old per-finding prompts in the UI: the shared role framing, workflow, and
// guardrails are stated ONCE, then every actionable finding is listed as a
// compact, prioritized section. Portable across any AI coding agent on any
// platform (plain, provider-neutral markdown only).
//
// Kept client-side and self-contained: it composes directly from the findings the
// report already holds, so there's no server round-trip or schema change. The
// per-finding `agentPrompt` field still exists for the programmatic MCP endpoint,
// where one prompt per finding is the right granularity.

const SEVERITY_RANK: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

// The findings worth handing to a coding agent: real (not suppressed) and
// actionable (info-level surface/coverage notes have no fix to make).
export function actionableFindings(findings: Finding[]): Finding[] {
  return findings
    .filter((f) => !f.isFalsePositive && f.severity !== 'info')
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
}

function severityCountLine(findings: Finding[]): string {
  const order: Severity[] = ['critical', 'high', 'medium', 'low'];
  const parts = order
    .map((s) => ({ s, n: findings.filter((f) => f.severity === s).length }))
    .filter(({ n }) => n > 0)
    .map(({ s, n }) => `${n} ${s}`);
  return parts.length ? parts.join(' · ') : 'none';
}

function findingSection(finding: Finding, index: number): string {
  const lines: string[] = [];
  lines.push(`### ${index}. [${finding.severity.toUpperCase()}] ${finding.title}`);
  const classification = [finding.category, finding.owasp ? `OWASP ${finding.owasp}` : '']
    .filter(Boolean)
    .join(' · ');
  if (classification) lines.push(`- Classification: ${classification}`);
  if (finding.endpoint) lines.push(`- Affected endpoint: ${finding.endpoint}`);
  if (finding.description) lines.push(`- What: ${finding.description}`);
  if (finding.impact) lines.push(`- Impact: ${finding.impact}`);
  if (finding.fix) lines.push(`- Fix: ${finding.fix}`);
  // Fold in a one-line reproduction when a replayable exploit receipt exists, so
  // the agent can confirm the flaw is real before touching code.
  const ev = finding.evidence;
  if (ev?.reproduction) {
    const signal = ev.signal?.quote ? ` → response contained ${JSON.stringify(ev.signal.quote)}` : '';
    lines.push(`- Proof (reproduce): \`${ev.reproduction}\`${signal}`);
  }
  return lines.join('\n');
}

export function buildScanFixPrompt(scan: Scan): string {
  const findings = actionableFindings(scan.findings || []);
  const posture = deriveSecurityPosture(scan.findings || []);
  const host = (() => {
    try { return new URL(scan.url).host; } catch { return scan.url; }
  })();

  if (findings.length === 0) {
    return [
      `# Security Remediation Plan — ${host}`,
      '',
      `A black-box security scan of ${scan.url} found no actionable issues to fix`,
      `(security score ${posture.score}/100 — ${posture.postureRating}). No code changes are required.`,
    ].join('\n');
  }

  const lines: string[] = [];

  // --- Role + task framing (stated once for the whole plan) ---
  lines.push(
    `# Security Remediation Plan — ${host}`,
    '',
    'You are a senior application security engineer with full write access to this',
    `repository. A black-box security scan of ${scan.url} found ${findings.length} issue(s) to fix.`,
    'Work through them IN THE ORDER LISTED (most severe first), fixing each at the',
    'root cause without regressions or weakening any other control. This prompt is',
    'self-contained, provider-neutral, and portable: it works the same with any AI',
    'coding agent on any platform.',
    '',
    'Scan context:',
    `- Target (black-box): ${scan.url}`,
    `- Security score: ${posture.score}/100 (${posture.postureRating})`,
    `- Issues to fix: ${severityCountLine(findings)}`,
  );

  // --- Shared workflow (applied to every finding) ---
  lines.push(
    '',
    '## How to work this plan',
    '1. Handle findings top-down (most severe first). For EACH finding:',
    '   a. Locate — this scan is black-box and never read your source, so search by',
    '      the described behavior/endpoint and name the responsible file(s).',
    "   b. Confirm — reproduce it before changing anything. If it doesn't actually",
    '      apply, mark it a likely false positive with your reasoning and move on.',
    '      Never invent a change just to satisfy this prompt.',
    "   c. Fix the root cause using the project's existing stack and conventions; if",
    '      the same flaw pattern repeats elsewhere, fix every instance.',
    '   d. Add a regression test that FAILS on the vulnerable code and PASSES after.',
    '2. After all fixes: run the FULL test suite, re-exercise each affected request,',
    '   and confirm nothing else broke.',
  );

  // --- Guardrails (stated once) ---
  lines.push(
    '',
    '## Global guardrails',
    '- Never weaken or remove another security control (auth, CORS, CSP, input',
    '  validation) to make a fix pass.',
    "- Keep each change minimal and reviewable; don't refactor unrelated code.",
    '- Never hardcode secrets or credentials. If a dependency upgrade is required,',
    '  pin the patched version and call out any breaking changes.',
    '- If a safe fix needs broader changes, stop and explain rather than guessing.',
  );

  // --- The findings themselves, prioritized and compact ---
  lines.push('', '## Findings to fix (in priority order)');
  findings.forEach((f, i) => {
    lines.push('', findingSection(f, i + 1));
  });

  // --- One acceptance checklist for the whole plan ---
  lines.push(
    '',
    '## Done when',
    '- [ ] Every finding above is fixed at the root cause, or explicitly justified as a false positive.',
    '- [ ] A regression test was added for each real fix.',
    '- [ ] The full test suite passes.',
    '- [ ] You have summarized, per finding: what changed, which files, and how you verified it.',
  );

  return lines.join('\n');
}
