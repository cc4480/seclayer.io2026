import { Finding, Severity, ExecutiveBreakdown } from '../src/types.js';
import { callDeepSeek, resolveApiKey } from './deepseekClient.js';
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

// Reconcile a model-authored finding list with machine-collected ground truth:
// discard any exploit-pillar (RED_TEAM/API_SEC) findings the model wrote and
// splice the compiled exploit findings back in verbatim, so a receipt-backed
// exploit is never reworded, softened, or dropped. Retained as a tested utility;
// the report pipeline no longer routes findings through the model at all (see
// generateAiReport), so it is not on the live path. Mutates and returns
// `finalFindings`.
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

// Corrects a model-picked category to a stronger one implied by the finding's
// title (the model tends to bucket everything as "DAST"). Retained as a tested
// utility; not on the live report path now that findings are compiled
// deterministically. Returns aiCategory unchanged when the title gives no signal.
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
  staticCompiled: { score: number; severity: Severity; findings: Finding[] },
  // Optional per-user "bring your own key" override (see resolveApiKey).
  apiKey?: string | null,
): Promise<{ score: number; severity: Severity; findings: Finding[]; aiSummary: string; aiReasoning?: string; executiveBreakdown: ExecutiveBreakdown }> {

  const effectiveKey = resolveApiKey(apiKey);
  if (!effectiveKey) {
    console.log("No DeepSeek API key available. Generating elegant local-mode executive summary.");
    const defaultSecSummary = compileLocalSummary(url, staticCompiled);
    return {
      ...staticCompiled,
      aiSummary: defaultSecSummary,
      executiveBreakdown: compileLocalBreakdown(url, staticCompiled),
    };
  }

  try {
    const prompt = buildReportPrompt(url, diagnostics, staticCompiled);

    const { content: bodyTextRaw, reasoningContent } = await callDeepSeek(MODEL_PRO, prompt, {
      thinking: 'enabled',
      reasoningEffort: 'high',
      // Reasoning + a findings-heavy JSON report share this budget — see
      // deepseekClient.ts's DeepSeekCallOptions doc for why it must be generous.
      maxTokens: 20000,
      // High-effort thinking mode over a large token budget legitimately takes
      // a while; generous but still bounded so a stalled call can't hang a
      // scan in "analyzing" forever (see deepseekClient.ts).
      timeoutMs: 90000,
    }, effectiveKey);
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

    // DETERMINISM: the finding list, severities, grouping and score come ONLY
    // from compileStaticFindings — a pure function of the measured diagnostics
    // (see server/findings.ts + server/scoring.ts). The model used to author the
    // non-exploit findings, and its run-to-run freedom to reword titles or to
    // MERGE vs SPLIT the same issue (e.g. reporting the two cookie flag gaps as
    // one finding on one run and two on the next) changed the finding count — and
    // therefore the recalculated score — for a target that had not changed. The
    // model now contributes only the NARRATIVE prose (executive summary +
    // breakdown); the findings panel and the score are fully reproducible.
    return {
      score: staticCompiled.score,
      severity: staticCompiled.severity,
      findings: staticCompiled.findings,
      aiSummary: data.aiSummary || compileLocalSummary(url, staticCompiled),
      aiReasoning: truncateReasoning(reasoningContent),
      executiveBreakdown: sanitizeBreakdown(data.executiveBreakdown, url, staticCompiled),
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
