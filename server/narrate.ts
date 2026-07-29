import { Finding, Severity } from "../src/types.js";
import { DiagnosticResult } from "./scanner.js";
import { callDeepSeek, resolveApiKey } from "./deepseekClient.js";
import type { LiveEvent } from "./scanEvents.js";

// Fast, cheap narration of scan progress for the live progress UI — distinct
// from server/deepseek.ts's pro-tier report generation. Flash runs with
// thinking explicitly disabled (we want a handful of short lines back
// quickly, not deep reasoning) and a small token budget. Always falls back to
// a deterministic local narration built from the same real data when no API
// key is configured or the call fails, so the progress feed is never fake —
// worst case it's just less polished prose.
const MODEL_FLASH = process.env.DEEPSEEK_MODEL_FLASH || 'deepseek-v4-flash';
const MAX_NARRATION_LINES = 6;
// The scanning phase gets a longer, more detailed feed than the analysis phase —
// it's the play-by-play of what the sweep actually did and found.
const MAX_SCANNING_LINES = 12;

function parseLines(content: string | null, maxLines = MAX_NARRATION_LINES): string[] | null {
  if (!content) return null;
  try {
    const data = JSON.parse(content.trim());
    if (Array.isArray(data.lines) && data.lines.length > 0) {
      return data.lines.slice(0, maxLines).map((l: unknown) => String(l).trim()).filter(Boolean);
    }
  } catch {
    // fall through to null
  }
  return null;
}

// Narrates what the diagnostic sweep (headers, secrets, libraries,
// subdomains, sensitive paths, crawl + active probes) actually found.
export async function narrateScanning(diag: DiagnosticResult, url: string, apiKey?: string | null): Promise<string[]> {
  const effectiveKey = resolveApiKey(apiKey);
  if (!effectiveKey) return localScanningNarration(diag);

  // Pull out the concrete, name-able details so flash narrates specifics rather
  // than bare counts.
  const liveSubs = diag.easmPerimeter.subdomains.filter((s) => s.status === 'live').map((s) => s.domain);
  const exposedPaths = diag.probedPaths.filter((p) => p.exposed).map((p) => p.path);
  const vulnLibs = diag.scaLibraries.map((l) => `${l.name}@${l.version}`);
  const secretIssues = diag.sastFindings.map((s) => s.issue);
  const exploitFindings = [
    ...(diag.redTeamFindings || []).map((f) => `${f.testName} [${f.severity}]`),
    ...(diag.apiSecFindings || []).map((f) => `${f.testName} [${f.severity}]`),
  ];

  try {
    const prompt = `You narrate a penetration-testing scanner's progress for a live terminal-style feed a
developer watches in real time. Using ONLY the facts below, write up to ${MAX_SCANNING_LINES} DETAILED,
specific, factual log lines (each up to 160 characters) that walk through what the scan of "${url}"
actually did and found across its recon + active-probe sweep. Name the concrete details — the exact
headers, paths, endpoints, libraries, and EACH confirmed exploit by name and severity — one line per
notable result. Be informative and precise, not terse; but no speculation, no filler, no markdown.
Order them roughly in scan order (fetch → perimeter/recon → crawl → active exploitation → summary).
Return JSON: {"lines": ["...", "..."]}.

FACTS:
- Fetched ${url} → HTTP ${diag.responseStatus}; transport ${diag.sslSecure ? 'HTTPS/TLS' : 'PLAINTEXT HTTP (no TLS)'}
- Server/tech signatures disclosed: ${diag.techLeaked.join(', ') || 'none'}
- Missing security headers (${diag.missingHeaders.length}): ${diag.missingHeaders.join(', ') || 'none'}
- Cookie flag issues: ${diag.cookieIssues.join('; ') || 'none'}
- Exposed secret signatures (${secretIssues.length}): ${secretIssues.slice(0, 5).join('; ') || 'none'}
- Vulnerable libraries: ${vulnLibs.join(', ') || 'none'}
- Perimeter: resolved IP ${diag.easmPerimeter.ip || 'n/a'}, nameserver ${diag.easmPerimeter.nameserver || 'n/a'}; ${liveSubs.length} live subdomain(s)${liveSubs.length ? `: ${liveSubs.slice(0, 6).join(', ')}` : ''}
- Exposed sensitive paths (${exposedPaths.length}): ${exposedPaths.join(', ') || 'none'}
- Crawl coverage: ${diag.crawl ? `${diag.crawl.pagesVisited} pages, ${diag.crawl.endpointsDiscovered} endpoints, ${diag.crawl.paramsTested} params fuzzed${diag.crawl.sampleEndpoints?.length ? `; e.g. ${diag.crawl.sampleEndpoints.slice(0, 4).join(', ')}` : ''}` : 'not run'}
- Active exploit probing: ${diag.activeProbesSkipped ? 'SKIPPED — domain ownership not verified (passive recon only)' : 'RAN — SQLi/XSS/cmd-injection/SSRF + aggressive tier (SSTI/LFI/XXE/CORS/CRLF/open-redirect/NoSQL)'}
- Confirmed exploit findings (${exploitFindings.length}): ${exploitFindings.slice(0, 10).join(' | ') || 'none confirmed'}`;

    const { content } = await callDeepSeek(MODEL_FLASH, prompt, { thinking: 'disabled', maxTokens: 1000, timeoutMs: 20000 }, effectiveKey);
    return parseLines(content, MAX_SCANNING_LINES) ?? localScanningNarration(diag);
  } catch (err: any) {
    console.warn(`[narrate] flash scanning narration failed, using local fallback: ${err?.message || err}`);
    return localScanningNarration(diag);
  }
}

// Live, incremental narration for the real-time ticker: given the newest raw
// probe/recon events, ask Flash for a couple of plain-English "what/why" lines,
// as if a senior pentester were talking the viewer through what's happening.
// Best-effort — returns [] on no key / no events / any failure, because the raw
// events already carry a built-in description, so the ticker is never left empty.
const MAX_LIVE_LINES = 3;

export async function narrateLiveBatch(
  events: LiveEvent[],
  url: string,
  apiKey?: string | null,
): Promise<string[]> {
  const effectiveKey = resolveApiKey(apiKey);
  if (!effectiveKey || events.length === 0) return [];
  const recent = events.slice(-12).map((e) => e.text);
  try {
    const prompt = `You are narrating a LIVE penetration test of "${url}" for a terminal feed a developer is
watching in real time. Below are the raw technical steps the scanner just performed (each is a probe it
fired or a recon result). In plain English, write up to ${MAX_LIVE_LINES} short lines (each under 120
characters) that explain WHAT is being attempted and WHY it matters — as a senior pentester talking the
viewer through it. Present tense, specific to THESE steps, no markdown, no filler, do not just repeat the
raw lines verbatim. Return JSON: {"lines": ["...", "..."]}.

RECENT STEPS:
${recent.map((t) => `- ${t}`).join("\n")}`;

    const { content } = await callDeepSeek(MODEL_FLASH, prompt, { thinking: "disabled", maxTokens: 300, timeoutMs: 8000 }, effectiveKey);
    return parseLines(content, MAX_LIVE_LINES) ?? [];
  } catch (err: any) {
    console.warn(`[narrate] live batch narration failed: ${err?.message || err}`);
    return [];
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
  apiKey?: string | null,
): Promise<string[]> {
  const scoreLine = `Posture score: ${compiled.score}/100 (${compiled.severity.toUpperCase()}).`;
  const effectiveKey = resolveApiKey(apiKey);
  if (!effectiveKey) return localAnalysisNarration(compiled);

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

    const { content } = await callDeepSeek(MODEL_FLASH, prompt, { thinking: 'disabled', maxTokens: 600, timeoutMs: 15000 }, effectiveKey);
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
  const lines: string[] = [];

  // Fetch + transport.
  lines.push(`Fetched ${diag.url} → HTTP ${diag.responseStatus}; transport ${diag.sslSecure ? 'HTTPS/TLS active' : 'PLAINTEXT HTTP — no TLS'}.`);

  // Server/tech fingerprint.
  if (diag.techLeaked.length) lines.push(`Server/tech fingerprint disclosed: ${diag.techLeaked.join(', ')}.`);

  // Defensive headers (name them).
  lines.push(diag.missingHeaders.length
    ? `Response headers: ${diag.missingHeaders.length} defensive header(s) missing — ${diag.missingHeaders.join(', ')}.`
    : `Response headers: all tracked defensive headers present.`);

  // Cookie hardening.
  if (diag.cookieIssues.length) lines.push(`Cookie hardening gaps: ${diag.cookieIssues.join('; ')}.`);

  // Secrets + vulnerable dependencies (name the libs).
  const vulnLibs = diag.scaLibraries.map((l) => `${l.name}@${l.version}`);
  if (diag.sastFindings.length || vulnLibs.length) {
    lines.push(`Composition: ${diag.sastFindings.length} exposed-secret signature(s); vulnerable dependencies: ${vulnLibs.join(', ') || 'none'}.`);
  }

  // Perimeter / EASM (name live subdomains).
  const liveSubs = diag.easmPerimeter.subdomains.filter((s) => s.status === 'live').map((s) => s.domain);
  lines.push(`Perimeter: resolved ${diag.easmPerimeter.ip || 'n/a'}, ${liveSubs.length} live subdomain(s)${liveSubs.length ? ` — ${liveSubs.slice(0, 5).join(', ')}` : ''}.`);

  // Sensitive-path probing (name exposed paths, or note locked down).
  const exposedPaths = diag.probedPaths.filter((p) => p.exposed).map((p) => p.path);
  lines.push(exposedPaths.length
    ? `Exposed sensitive path(s): ${exposedPaths.join(', ')}.`
    : `Sensitive-path probe: ${diag.probedPaths.length} path(s) checked, none exposed (locked down).`);

  // Crawl coverage with sample endpoints.
  if (diag.crawl) {
    lines.push(`Crawled ${diag.crawl.pagesVisited} page(s); mapped ${diag.crawl.endpointsDiscovered} endpoint(s), fuzzed ${diag.crawl.paramsTested} param(s)${diag.crawl.sampleEndpoints?.length ? ` — e.g. ${diag.crawl.sampleEndpoints.slice(0, 3).join(', ')}` : ''}.`);
  }

  // Active exploitation + each confirmed finding by name.
  if (diag.activeProbesSkipped) {
    lines.push(`Active exploit probing skipped — domain ownership not verified (passive recon only).`);
  } else {
    lines.push(`Active exploit probes ran: SQLi/XSS/cmd-injection/SSRF + aggressive tier (SSTI/LFI/XXE/CORS/CRLF/open-redirect/NoSQL).`);
    const exploits = [
      ...(diag.redTeamFindings || []).map((f) => `${f.testName} [${f.severity}]`),
      ...(diag.apiSecFindings || []).map((f) => `${f.testName} [${f.severity}]`),
    ];
    if (exploits.length) {
      // One line per confirmed exploit (bounded by the overall line cap below).
      for (const e of exploits.slice(0, 8)) lines.push(`  ⮡ Confirmed: ${e}`);
    } else {
      lines.push(`No exploit confirmed by the active probes on this target.`);
    }
  }

  return lines.slice(0, MAX_SCANNING_LINES);
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
