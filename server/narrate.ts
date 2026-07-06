import { Finding, Severity } from "../src/types.js";
import { DiagnosticResult } from "./scanner.js";
import { callDeepSeek, getApiKey } from "./deepseekClient.js";

// Fast, cheap narration of scan progress for the live progress UI — distinct
// from server/deepseek.ts's pro-tier report generation. Flash runs with
// thinking explicitly disabled (we want a handful of short lines back
// quickly, not deep reasoning) and a small token budget. Always falls back to
// a deterministic local narration built from the same real data when no API
// key is configured or the call fails, so the progress feed is never fake —
// worst case it's just less polished prose.
const MODEL_FLASH = process.env.DEEPSEEK_MODEL_FLASH || 'deepseek-v4-flash';
const MAX_NARRATION_LINES = 6;

function parseLines(content: string | null): string[] | null {
  if (!content) return null;
  try {
    const data = JSON.parse(content.trim());
    if (Array.isArray(data.lines) && data.lines.length > 0) {
      return data.lines.slice(0, MAX_NARRATION_LINES).map((l: unknown) => String(l).trim()).filter(Boolean);
    }
  } catch {
    // fall through to null
  }
  return null;
}

// Narrates what the diagnostic sweep (headers, secrets, libraries,
// subdomains, sensitive paths, crawl + active probes) actually found.
export async function narrateScanning(diag: DiagnosticResult, url: string): Promise<string[]> {
  if (!getApiKey()) return localScanningNarration(diag);

  try {
    const prompt = `You narrate a security scanner's progress for a live terminal-style progress feed a
developer is watching in real time. Using ONLY the facts below, write up to ${MAX_NARRATION_LINES}
short, punchy, factual log lines (each under 100 characters) describing what the scan of "${url}"
just found during its diagnostic sweep. No speculation, no filler, no markdown — just terse status
lines a security tool would log. Return JSON: {"lines": ["...", "..."]}.

FACTS:
- HTTP status: ${diag.responseStatus}, TLS: ${diag.sslSecure ? 'enabled' : 'missing'}
- Missing security headers: ${diag.missingHeaders.join(', ') || 'none'}
- Tech/framework signatures leaked: ${diag.techLeaked.join(', ') || 'none'}
- Cookie issues: ${diag.cookieIssues.join(', ') || 'none'}
- Exposed secret signatures: ${diag.sastFindings.length}
- Vulnerable libraries detected: ${diag.scaLibraries.map(l => l.name).join(', ') || 'none'}
- Live subdomains found: ${diag.easmPerimeter.subdomains.filter(s => s.status === 'live').length}
- Exposed sensitive paths: ${diag.probedPaths.filter(p => p.exposed).map(p => p.path).join(', ') || 'none'}
- Crawl: ${diag.crawl ? `${diag.crawl.pagesVisited} pages, ${diag.crawl.endpointsDiscovered} endpoints, ${diag.crawl.paramsTested} params fuzzed` : 'not run'}
- Active exploit probes run: ${diag.activeProbesSkipped ? 'no (unverified domain)' : 'yes'}
- Red-team/API findings so far: ${(diag.redTeamFindings?.length || 0) + (diag.apiSecFindings?.length || 0)}`;

    const { content } = await callDeepSeek(MODEL_FLASH, prompt, { thinking: 'disabled', maxTokens: 600 });
    return parseLines(content) ?? localScanningNarration(diag);
  } catch (err: any) {
    console.warn(`[narrate] flash scanning narration failed, using local fallback: ${err?.message || err}`);
    return localScanningNarration(diag);
  }
}

// Matches a line that appears to be (re)stating the N/100 score, so it can be
// dropped in favor of our own authoritative one — flash occasionally
// paraphrases the exact digits wrong even when handed them as a fact.
const SCORE_LINE_PATTERN = /\b\d{1,3}\s*\/\s*100\b/;

// Narrates the outcome of the analysis phase (scoring + findings).
export async function narrateAnalysis(
  compiled: { score: number; severity: Severity; findings: Finding[] },
  url: string,
): Promise<string[]> {
  const scoreLine = `Posture score: ${compiled.score}/100 (${compiled.severity.toUpperCase()}).`;
  if (!getApiKey()) return localAnalysisNarration(compiled);

  try {
    const bySeverity = countBySeverity(compiled.findings);
    const prompt = `You narrate a security scanner's progress for a live terminal-style progress feed a
developer is watching in real time. Using ONLY the facts below, write up to ${MAX_NARRATION_LINES}
short, punchy, factual log lines (each under 100 characters) describing the analysis phase for
"${url}" — findings compiled by severity. Do NOT state the posture score yourself (it's appended
separately, verbatim, afterward). No speculation, no filler, no markdown. Return
JSON: {"lines": ["...", "..."]}.

FACTS:
- Total findings: ${compiled.findings.length} (critical: ${bySeverity.critical}, high: ${bySeverity.high}, medium: ${bySeverity.medium}, low: ${bySeverity.low}, info: ${bySeverity.info})
- Overall severity: ${compiled.severity}
- Top finding: ${compiled.findings[0]?.title || 'none'}`;

    const { content } = await callDeepSeek(MODEL_FLASH, prompt, { thinking: 'disabled', maxTokens: 600 });
    const modelLines = parseLines(content);
    if (!modelLines) return localAnalysisNarration(compiled);
    // Belt-and-suspenders: even though the prompt says not to, strip any line
    // that still looks like a score restatement before appending the real one.
    const filtered = modelLines.filter((l) => !SCORE_LINE_PATTERN.test(l));
    return [...filtered, scoreLine].slice(0, MAX_NARRATION_LINES + 1);
  } catch (err: any) {
    console.warn(`[narrate] flash analysis narration failed, using local fallback: ${err?.message || err}`);
    return localAnalysisNarration(compiled);
  }
}

function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  return counts;
}

function localScanningNarration(diag: DiagnosticResult): string[] {
  const lines: string[] = [
    `Fetched ${diag.url}: HTTP ${diag.responseStatus}, TLS ${diag.sslSecure ? 'active' : 'MISSING'}.`,
    `${diag.missingHeaders.length} security header(s) missing${diag.missingHeaders.length ? `: ${diag.missingHeaders.join(', ')}` : ''}.`,
  ];
  const secretsAndLibs = diag.sastFindings.length + diag.scaLibraries.length;
  if (secretsAndLibs > 0) {
    lines.push(`${diag.sastFindings.length} exposed secret signature(s), ${diag.scaLibraries.length} vulnerable librar${diag.scaLibraries.length === 1 ? 'y' : 'ies'} detected.`);
  }
  const liveSubdomains = diag.easmPerimeter.subdomains.filter((s) => s.status === 'live').length;
  const exposedPaths = diag.probedPaths.filter((p) => p.exposed).length;
  lines.push(`${liveSubdomains} live subdomain(s), ${exposedPaths} exposed sensitive path(s) found.`);
  if (diag.crawl) {
    lines.push(`Crawled ${diag.crawl.pagesVisited} page(s), discovered ${diag.crawl.endpointsDiscovered} endpoint(s).`);
  }
  lines.push(diag.activeProbesSkipped
    ? 'Active exploit probes skipped (domain not verified).'
    : 'Active SQLi/XSS/SSRF/API exploit probes completed.');
  return lines.slice(0, MAX_NARRATION_LINES);
}

function localAnalysisNarration(compiled: { score: number; severity: Severity; findings: Finding[] }): string[] {
  const bySeverity = countBySeverity(compiled.findings);
  const lines = [
    `Compiled ${compiled.findings.length} finding(s) — ${bySeverity.critical} critical, ${bySeverity.high} high, ${bySeverity.medium} medium.`,
    `Posture score: ${compiled.score}/100 (${compiled.severity.toUpperCase()}).`,
  ];
  if (compiled.findings[0]) lines.push(`Top issue: ${compiled.findings[0].title}.`);
  return lines.slice(0, MAX_NARRATION_LINES);
}
