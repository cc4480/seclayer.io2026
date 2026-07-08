import crypto from "crypto";
import { Finding, Severity, ExecutiveBreakdown } from '../src/types.js';
import { mapOwasp } from './owasp.js';
import { buildAgentPrompt, buildImpactFallback } from './agentPrompt.js';
import { callDeepSeek, getApiKey } from './deepseekClient.js';

// The "pro" tier handles the deep security report reasoning. It defaults to
// "thinking" mode (chain-of-thought before the final answer) — see
// deepseekClient.ts's DeepSeekCallOptions for why max_tokens has to account
// for that. (The "flash" tier handles fast scan-progress narration — see
// server/narrate.ts.)
const MODEL_PRO = process.env.DEEPSEEK_MODEL_PRO || 'deepseek-v4-pro';

// The active-exploit pillars are authored entirely by the scanner, never the model.
const EXPLOIT_CATEGORIES = new Set(['RED_TEAM', 'API_SEC']);

// Reconcile the model's finding list with machine-collected ground truth. Exploit
// findings (RED_TEAM/API_SEC) carry receipts the scanner captured live — the model
// must not author, reword, drop, or soften them. So we discard any exploit-pillar
// findings the model wrote (it tends to rephrase "Active SQL Injection Probe" into
// "SQL Injection", which would otherwise double-list next to the PROVEN original)
// and splice the compiled exploit findings back in verbatim. The model keeps
// ownership of everything else (headers, TLS, SCA, perimeter, etc.). Mutates and
// returns `finalFindings`.
export function reattachEvidence(finalFindings: Finding[], staticFindings: Finding[]): Finding[] {
  const reconciled = finalFindings.filter((f) => !EXPLOIT_CATEGORIES.has(f.category));
  for (const orig of staticFindings) {
    if (EXPLOIT_CATEGORIES.has(orig.category)) reconciled.push(orig);
  }
  finalFindings.length = 0;
  finalFindings.push(...reconciled);
  return finalFindings;
}

// The chain-of-thought can run long; cap what we persist/display.
const MAX_REASONING_CHARS = 8000;
function truncateReasoning(text: string | undefined): string | undefined {
  if (!text) return undefined;
  return text.length > MAX_REASONING_CHARS ? text.slice(0, MAX_REASONING_CHARS) + '…' : text;
}

// The model tends to lazily bucket most findings as "DAST", which collapses the
// report's seven category pillars into one and makes them meaningless. A
// finding's TITLE is a far stronger signal than the label the model picked, so
// correct obvious mismatches deterministically. Returns aiCategory unchanged
// when the title gives no strong signal.
export function refineCategory(aiCategory: string, title: string): string {
  const t = (title || '').toLowerCase();
  // Defensive headers, cookies, session policy → IAST
  if (/content-security-policy|\bcsp\b|strict-transport|\bhsts\b|x-frame|clickjack|x-content-type|referrer-policy|\bcookie\b|samesite|httponly|secure attribute/.test(t)) return 'IAST';
  // Perimeter / external attack surface → EASM
  if (/framework signature|framework disclosure|verbose server|server (banner|header|version)|x-powered-by|\bsubdomain\b|nameserver|\bdns\b|insecure connection|plaintext http|cleartext|\btls\b|\bssl\b|certificate/.test(t)) return 'EASM';
  // Exposed secrets in client-served code → SAST
  if (/exposed credential|hardcoded|\bapi key\b|secret key|private key|access key|credential signature/.test(t)) return 'SAST';
  // Vulnerable / outdated dependencies → SCA
  if (/outdated library|vulnerable (library|component|dependency)|end-of-life|\bcve-\d/.test(t)) return 'SCA';
  return aiCategory;
}

export async function generateAiReport(
  url: string,
  diagnostics: any,
  staticCompiled: { score: number; severity: Severity; findings: Finding[] }
): Promise<{ score: number; severity: Severity; findings: Finding[]; aiSummary: string; aiReasoning?: string; executiveBreakdown: ExecutiveBreakdown }> {

  if (!getApiKey()) {
    console.log("No valid DEEPSEEK_API_KEY set. Generating elegant local-mode executive summary.");
    const defaultSecSummary = compileLocalSummary(url, staticCompiled);
    return {
      ...staticCompiled,
      aiSummary: defaultSecSummary,
      executiveBreakdown: compileLocalBreakdown(url, staticCompiled),
    };
  }

  try {
    const findingsSummaryText = staticCompiled.findings.map(f => `- [${f.severity.toUpperCase()}] ${f.title}: ${f.description} (Fix: ${f.fix})`).join('\n');
    const techContext = diagnostics.techLeaked?.length ? diagnostics.techLeaked.join(', ') : 'no framework/server signature leaked';
    const activeProbesSkipped = !!diagnostics.activeProbesSkipped;
    // Summarize the sensitive-path probe outcomes so the model treats a
    // locked-down path (403/404) as a PASS, not a finding.
    const lockedDownPaths = (diagnostics.probedPaths || []).filter((p: any) => !p.exposed).map((p: any) => p.path);
    const exposedPaths = (diagnostics.probedPaths || []).filter((p: any) => p.exposed).map((p: any) => p.path);

    const prompt = `You are Seclayer's automated penetration testing AI, reviewing a completed black-box scan
before it ships to a developer as their audit report. Think through the evidence carefully — this
report is what the developer's team will act on directly, including handing pieces of it straight
to an AI coding agent (Cursor, Claude Code, Windsurf) to implement the fixes.

Analyze the following black-box scanner diagnostics for target web url: "${url}" and the compiled issues listed below.
Generate a structured penetration testing report output in JSON format.

DIAGNOSTIC DATA:
Response Status Code: ${diagnostics.responseStatus}
SSL Encryption Active: ${diagnostics.sslSecure}
Missing Essential Defensive Security Headers (observed absent on the scanned response; may be served conditionally elsewhere): ${diagnostics.missingHeaders.join(', ') || 'none'}
Technology Framework Signature Leaks: ${techContext}
Sensitive paths that are LOCKED DOWN (403/404 — these are PASSES, not issues): ${lockedDownPaths.join(', ') || 'none'}
Sensitive paths CONFIRMED EXPOSED (real findings): ${exposedPaths.join(', ') || 'none'}
Cookie Configuration Flags: ${JSON.stringify(diagnostics.cookieIssues)}
Active Exploitation Testing (SQLi / XSS / command-injection / SSRF / GraphQL / BOLA): ${activeProbesSkipped ? 'NOT PERFORMED — domain ownership was not verified, so ONLY passive recon ran. No active exploit probe fired against this target.' : 'performed against the target'}

DETECTED ISSUES:
${findingsSummaryText}

FALSE POSITIVE FILTERING (CRITICAL):
- Aggressively filter out noise, theoretical vulnerabilities, and duplicate findings.
- Sensitive paths that returned 403/404 (e.g. /.env, /.git/config, /admin) are PASSES — the target is correctly locked down. NEVER report them as findings; they are positive signals of good hygiene, not issues.
- Missing security headers (CSP, HSTS, X-Frame-Options) are defense-in-depth GAPS, not exploitable vulnerabilities on their own. Rate them "medium" at most, and "low" (or omit) when the rest of the surface is well-hardened. NEVER rate a missing header "high" or "critical". Large, well-run sites also sometimes serve these headers only on certain routes, so do not over-state confidence that they are truly absent.
- Consolidate multiple similar issues into a single actionable finding.
- Do NOT hallucinate vulnerabilities that are not supported by the DIAGNOSTIC DATA or DETECTED ISSUES.
${activeProbesSkipped ? '- ACTIVE EXPLOITATION DID NOT RUN. You MUST NOT emit any finding in the "RED_TEAM" category, MUST NOT claim any injection/XSS/SSRF/command-injection/BOLA/GraphQL vulnerability was found or tested, and MUST NOT present these pillars as having results. It is correct and expected that active probing was skipped for an unverified domain — describe it as a scan-coverage note (info severity, DAST category) at most, not a vulnerability.' : '- Only report active-exploitation findings that the probes actually confirmed via a real signature match.'}

Please return a JSON object containing exactly these keys:
1. "aiSummary": A direct, plain-English, professional executive summary paragraph (3-5 sentences) summarizing overall posture, potential risks, and urgency level. Speak with the authority of an active principal cybersecurity assessor. Do NOT use fake placeholders like "example.com", you MUST explicitly mention the target url "${url}" in your summary. Do NOT use markdown links.
2. "adjustedScore": An integer safety score from 0 to 100 based on the severity of the findings (e.g. critical items lower score near 10-30, high items live around 40-60, clean sites get 90+).
3. "executiveBreakdown": A detailed, multi-part breakdown for a developer/engineering-lead audience — this is the DEEP report, not a repeat of "aiSummary". Object with exactly these fields:
   - "overview": 2-4 sentences of context on what was tested and the overall posture story (not identical wording to "aiSummary").
   - "riskAreas": an array of 3-6 objects, each { "area": short theme name (e.g. "Injection & Input Validation", "Transport & Perimeter Security", "Attack Surface Exposure", "Dependency Hygiene"), "detail": 1-2 sentences on what was actually found in that theme for "${url}" and why it matters }. Group the DETECTED ISSUES into these themes yourself — don't just restate each finding 1:1.
   - "businessImpact": 2-3 sentences framing the real-world consequence in business terms (data exposure, downtime, reputational/compliance risk, financial cost) if the current issues go unaddressed.
   - "priorityActions": an array of 3-6 short, ranked, imperative action items (most urgent first) a team should do this week — concrete engineering tasks, not vague advice.
4. "findings": An array corresponding to the detected issues, rewritten with clearer titles/descriptions of how an attacker would exploit the issue. Each item MUST have exactly these fields:
   - "title": short, specific vulnerability name.
   - "description": how an attacker would actually exploit this against "${url}".
   - "severity": one of "info", "low", "medium", "high", "critical".
   - "category": strictly one of "DAST", "SAST", "IAST", "SCA", "EASM", "RED_TEAM".
   - "fix": exactly how a developer would remediate this — concrete, and tailored to the detected stack (${techContext}) where that narrows it down.
   - "impact": one plain-English sentence on the real-world consequence if this is exploited (data/access/business impact) — do not just restate the description.
   - "agentPrompt": a ready-to-paste, numbered instruction block a developer could hand directly to their own AI coding agent (Cursor, Claude Code, etc.) to locate this exact issue in their codebase and fix it. Reference the detected stack (${techContext}) if it narrows down where to look, name the vulnerable pattern to search for, the concrete secure replacement, and a verification step. Write it as a clean, self-contained engineering instruction — do not mention Seclayer, "the scan", or this report inside the prompt text itself.
   Replace any generic placeholder domains (like example.com) with the real target "${url}".

Ensure the returned output is strictly valid JSON compliant with the required structure.`;

    const { content: bodyTextRaw, reasoningContent } = await callDeepSeek(MODEL_PRO, prompt, {
      thinking: 'enabled',
      reasoningEffort: 'high',
      // Reasoning + a findings-heavy JSON report share this budget — see
      // deepseekClient.ts's DeepSeekCallOptions doc for why it must be generous.
      maxTokens: 20000,
    });
    if (!bodyTextRaw) {
      return { ...staticCompiled, aiSummary: compileLocalSummary(url, staticCompiled), executiveBreakdown: compileLocalBreakdown(url, staticCompiled) };
    }

    let bodyText = bodyTextRaw.trim();
    try {
        const u = url.startsWith('http') ? url : `https://${url}`;
        const parsedUrl = new URL(u);
        bodyText = bodyText.replace(/example\.com/gi, parsedUrl.hostname);
        bodyText = bodyText.replace(/yourdomain\.com/gi, parsedUrl.hostname);
    } catch(e) {}
    const data = JSON.parse(bodyText);

    // Safeguard values
    const finalScore = Math.max(10, Math.min(100, Number(data.adjustedScore ?? staticCompiled.score)));
    const finalFindings: Finding[] = (data.findings || []).map((f: any, idx: number) => {
      const title = f.title || 'Vulnerability Finding';
      const category = (() => {
        const mapped = (() => {
          const cat = String(f.category || '').toUpperCase().replace(' ', '_');
          if (['DAST', 'SAST', 'IAST', 'SCA', 'EASM', 'RED_TEAM'].includes(cat)) return cat;
          if (cat.includes('RED') || cat.includes('TEAM') || cat.includes('FUZZ') || cat.includes('EXPLOIT')) return 'RED_TEAM';
          if (cat.includes('STATIC') || cat.includes('CODE') || cat.includes('SECRET') || cat.includes('KEY')) return 'SAST';
          if (cat.includes('DEPEND') || cat.includes('LIBRAR') || cat.includes('COMPOSIT') || cat.includes('SOFTWARE')) return 'SCA';
          if (cat.includes('INTERFACE') || cat.includes('INTERACT') || cat.includes('COOKIE') || cat.includes('SESSION')) return 'IAST';
          if (cat.includes('SURFACE') || cat.includes('DNS') || cat.includes('PORT') || cat.includes('ATTACK') || cat.includes('SSL') || cat.includes('DOMAIN') || cat.includes('CERT')) return 'EASM';
          return 'DAST';
        })();
        // Correct the model's lazy "everything is DAST" bucketing using the
        // title, so the report's category pillars stay meaningful.
        const refined = refineCategory(mapped, title);
        // No active probing ran → nothing can legitimately be an active-exploit
        // finding. Re-slot any RED_TEAM/API_SEC mis-categorization (e.g. the
        // "active probing skipped" notice, which mentions SQLi/XSS/etc.) to DAST
        // so those pillars never show counts for probes that never fired.
        if (activeProbesSkipped && (refined === 'RED_TEAM' || refined === 'API_SEC')) return 'DAST';
        return refined;
      })();
      let severity = (['info', 'low', 'medium', 'high', 'critical'].includes(f.severity?.toLowerCase()) ? f.severity.toLowerCase() : 'low') as Severity;
      // Missing-security-header findings are defense-in-depth gaps — clamp any
      // AI over-rating to medium so an absent (or conditionally-served) header
      // can never dominate a report as high/critical.
      if ((severity === 'high' || severity === 'critical') &&
          /content-security-policy|\bcsp\b|strict-transport|\bhsts\b|x-frame-options|clickjack|x-content-type|referrer-policy/i.test(title)) {
        severity = 'medium';
      }
      const fix = f.fix || '';
      // Carry a confidence signal so the report can split findings into
      // "Confirmed" vs "Needs Verification" (see scoring.isConfirmed). Prefer the
      // model's own value when valid; otherwise infer: a possibly-absent
      // defense-in-depth header is heuristic ("medium" — needs verification),
      // while everything else here is backed by direct diagnostic evidence and
      // is treated as confirmed ("high").
      const isHeaderGap = /content-security-policy|\bcsp\b|strict-transport|\bhsts\b|x-frame-options|clickjack|x-content-type|referrer-policy/i.test(title);
      const confidence: 'low' | 'medium' | 'high' =
        (f.confidence === 'low' || f.confidence === 'medium' || f.confidence === 'high')
          ? f.confidence
          : isHeaderGap ? 'medium' : 'high';
      return {
        id: `f_gen_${idx}_${crypto.randomUUID().slice(0,4)}`,
        title,
        description: f.description || '',
        severity,
        confidence,
        fix,
        category,
        owasp: mapOwasp(category, title),
        // The model is asked for both; these are the guaranteed fallback if
        // it omits one for a given finding.
        impact: typeof f.impact === 'string' && f.impact.trim() ? f.impact.trim() : buildImpactFallback(severity),
        agentPrompt: typeof f.agentPrompt === 'string' && f.agentPrompt.trim()
          ? f.agentPrompt.trim()
          : buildAgentPrompt({ title, description: f.description || '', fix, category, owasp: mapOwasp(category, title) }, url),
      };
    });

    // Re-attach machine-collected ground truth the model must never author or drop.
    reattachEvidence(finalFindings, staticCompiled.findings);

    // Find highest severity from findings
    let finalSeverity: Severity = 'low';
    if (finalFindings.some(f => f.severity === 'critical')) finalSeverity = 'critical';
    else if (finalFindings.some(f => f.severity === 'high')) finalSeverity = 'high';
    else if (finalFindings.some(f => f.severity === 'medium')) finalSeverity = 'medium';
    else if (finalFindings.some(f => f.severity === 'low')) finalSeverity = 'low';

    const finalFindingsForBreakdown = finalFindings.length > 0 ? finalFindings : staticCompiled.findings;
    return {
      score: finalScore,
      severity: finalSeverity,
      findings: finalFindingsForBreakdown,
      aiSummary: data.aiSummary || compileLocalSummary(url, staticCompiled),
      aiReasoning: truncateReasoning(reasoningContent),
      executiveBreakdown: sanitizeBreakdown(data.executiveBreakdown, url, { score: finalScore, severity: finalSeverity, findings: finalFindingsForBreakdown }),
    };

  } catch (err: any) {
    console.warn(`DeepSeek API call or parsing failed, using high-quality local summary: ${err?.message || err}`);
    return {
      ...staticCompiled,
      aiSummary: compileLocalSummary(url, staticCompiled),
      executiveBreakdown: compileLocalBreakdown(url, staticCompiled),
    };
  }
}

function compileLocalSummary(url: string, sc: { score: number; severity: Severity; findings: Finding[] }): string {
  if (sc.severity === 'critical' || sc.severity === 'high') {
    return `Seclayer security scan for ${url} has identified several severe security perimeters leaks. Multiple high or critical level configuration issues have been detected, presenting actionable vectors for unauthorized access, data exposure, or client hijacking. Remediation of dotfile policies and deploying standard script isolation wrappers should be handled as an urgent engineering requirement to protect customer resources.`;
  }
  if (sc.severity === 'medium') {
    return `Seclayer security assessment for ${url} indicates moderate vulnerability flags are present. Key defensive layers (including SSL redirection pipelines, XSS protection boundaries, or secure session cookie directives) are absent or require strict consolidation. While not presenting an immediate server compromise, hardening these perimeter checkpoints aligns with standard production guidelines.`;
  }
  return `Seclayer verification scanner reports that ${url} displays strong basic defensive hygiene. No critical system exposures or active data leaks were detected. To reach industry-leading status, minor improvements should be introduced to satisfy full HSTS preload targets and deploy advanced content routing headers.`;
}

// Deterministic, always-available executive breakdown built from the real
// compiled findings — used when DeepSeek isn't configured, the call fails,
// or (per-field, via sanitizeBreakdown) when the model omits a piece.
function compileLocalBreakdown(url: string, sc: { score: number; severity: Severity; findings: Finding[] }): ExecutiveBreakdown {
  const active = sc.findings.filter((f) => !f.isFalsePositive);
  const byCategory = new Map<string, Finding[]>();
  for (const f of active) {
    const list = byCategory.get(f.category) || [];
    list.push(f);
    byCategory.set(f.category, list);
  }
  const categoryLabels: Record<string, string> = {
    SAST: 'Static Code & Secrets Exposure', DAST: 'Dynamic Exploit Surface', IAST: 'Defensive Header & Session Policy',
    SCA: 'Dependency Hygiene', EASM: 'External Attack Surface', RED_TEAM: 'Active Exploit Probes', API_SEC: 'API Security',
  };
  const riskAreas = Array.from(byCategory.entries())
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 6)
    .map(([category, findings]) => ({
      area: categoryLabels[category] || category,
      detail: `${findings.length} finding(s), including "${findings[0].title}".`,
    }));

  const severityRank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const priorityActions = [...active]
    .sort((a, b) => severityRank[b.severity] - severityRank[a.severity])
    .slice(0, 6)
    .map((f) => f.fix || f.title);

  return {
    overview: `Automated black-box assessment of ${url}: ${active.length} active finding(s) across ${byCategory.size} area(s), posture score ${sc.score}/100 (${sc.severity}).`,
    riskAreas: riskAreas.length > 0 ? riskAreas : [{ area: 'General Hygiene', detail: 'No active findings — baseline defensive posture looks clean.' }],
    businessImpact: sc.severity === 'critical' || sc.severity === 'high'
      ? 'Unaddressed, these issues create a realistic path to data exposure, account compromise, or service disruption — with attendant customer-trust and compliance fallout.'
      : sc.severity === 'medium'
        ? 'Current gaps are unlikely to cause an immediate breach on their own but weaken defense-in-depth and could compound with future issues.'
        : 'No material business risk identified from this pass; continued monitoring is still recommended as the app evolves.',
    priorityActions: priorityActions.length > 0 ? priorityActions : ['No action required — no active findings this scan.'],
  };
}

const MAX_RISK_AREAS = 6;
const MAX_PRIORITY_ACTIONS = 6;

// Defensively merges the model's executiveBreakdown with the local
// deterministic one, field by field — the model's JSON is free-form input
// and any field can be missing, wrong-shaped, or empty.
function sanitizeBreakdown(
  raw: any,
  url: string,
  sc: { score: number; severity: Severity; findings: Finding[] },
): ExecutiveBreakdown {
  const fallback = compileLocalBreakdown(url, sc);
  if (!raw || typeof raw !== 'object') return fallback;

  const overview = typeof raw.overview === 'string' && raw.overview.trim() ? raw.overview.trim() : fallback.overview;

  const riskAreas = Array.isArray(raw.riskAreas)
    ? raw.riskAreas
        .filter((r: any) => r && typeof r.area === 'string' && r.area.trim() && typeof r.detail === 'string' && r.detail.trim())
        .slice(0, MAX_RISK_AREAS)
        .map((r: any) => ({ area: r.area.trim(), detail: r.detail.trim() }))
    : [];

  const businessImpact = typeof raw.businessImpact === 'string' && raw.businessImpact.trim()
    ? raw.businessImpact.trim()
    : fallback.businessImpact;

  const priorityActions = Array.isArray(raw.priorityActions)
    ? raw.priorityActions.map((a: unknown) => String(a).trim()).filter(Boolean).slice(0, MAX_PRIORITY_ACTIONS)
    : [];

  return {
    overview,
    riskAreas: riskAreas.length > 0 ? riskAreas : fallback.riskAreas,
    businessImpact,
    priorityActions: priorityActions.length > 0 ? priorityActions : fallback.priorityActions,
  };
}
