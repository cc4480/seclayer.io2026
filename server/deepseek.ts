import crypto from "crypto";
import { Finding, Severity, ExecutiveBreakdown } from '../src/types.js';
import { mapOwasp } from './owasp.js';
import { buildAgentPrompt, buildImpactFallback } from './agentPrompt.js';
import { callDeepSeek, getApiKey } from './deepseekClient.js';
import { buildReportPrompt } from './reportPrompt.js';
import { compileLocalSummary, compileLocalBreakdown, sanitizeBreakdown } from './localReport.js';

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
    const activeProbesSkipped = !!diagnostics.activeProbesSkipped;
    const prompt = buildReportPrompt(url, diagnostics, staticCompiled);

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
