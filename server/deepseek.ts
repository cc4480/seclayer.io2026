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

// Reasoning and the final answer share this budget (see deepseekClient.ts).
// Named so the empty-content log below can report spend against it.
const MAX_REPORT_TOKENS = 32000;

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

// Merge the model's PROSE onto the static findings.
//
// The model's finding list is deliberately not authoritative (see the
// DETERMINISM note in generateAiReport): identity, severity, grouping and score
// come only from compileStaticFindings. But the model is also asked, in
// server/reportPrompt.ts, to author the per-finding PROSE that cannot move the
// score: `description`, `fix`, `impact` and `agentPrompt`. All of it was being
// dropped along with the rest of the model's array, so every report shipped the
// generic static text even though a sharper, target- and stack-specific version
// had already been generated and paid for on every single scan. Both fix-prompt
// surfaces were affected: the MCP endpoint's per-finding `agentPrompt`, and the
// report UI's "Complete Fix Prompt" (src/lib/scanFixPrompt.ts), which composes
// from `description`/`impact`/`fix`.
//
// Exploit-pillar findings (RED_TEAM/API_SEC) are skipped entirely. They carry a
// replayable receipt, and reattachEvidence exists precisely so a proven exploit
// is never reworded or softened by the model; that invariant holds here too.
//
// Matching is by `sourceTitles` — the verbatim static titles the model says
// each of its findings covers — because the prompt explicitly tells it to
// reword titles and to consolidate similar issues, so neither its titles nor
// its array length line up with the static list. A consolidated finding applies
// its prompt to every issue it absorbed. Anything unmatched keeps the static
// fallback, so this can only ever upgrade a report, never blank one out.
export function mergeModelProse(staticFindings: Finding[], modelFindings: unknown): Finding[] {
  const merged = staticFindings.map((f) => ({ ...f }));
  if (!Array.isArray(modelFindings)) return merged;

  const byTitle = new Map<string, Finding>();
  for (const f of merged) byTitle.set(f.title.trim().toLowerCase(), f);

  for (const m of modelFindings as any[]) {
    const titles = Array.isArray(m?.sourceTitles) ? m.sourceTitles : [];
    for (const t of titles) {
      if (typeof t !== 'string') continue;
      const target = byTitle.get(t.trim().toLowerCase());
      if (!target) continue;
      if (EXPLOIT_CATEGORIES.has(target.category)) continue;
      for (const field of ['description', 'fix', 'impact', 'agentPrompt'] as const) {
        const v = m[field];
        if (typeof v === 'string' && v.trim()) target[field] = v.trim();
      }
    }
  }
  return merged;
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

    const { content: bodyTextRaw, reasoningContent, finishReason, completionTokens } = await callDeepSeek(MODEL_PRO, prompt, {
      thinking: 'enabled',
      reasoningEffort: 'high',
      // Reasoning + a findings-heavy JSON report SHARE this budget (see
      // deepseekClient.ts's DeepSeekCallOptions doc). In high-effort thinking
      // mode the chain-of-thought alone routinely consumes ~13-15k tokens, so a
      // 20k cap left too little for the final answer: the JSON report got
      // truncated mid-string and JSON.parse threw, silently degrading every
      // report to the local summary. Sized generously so reasoning AND a full
      // findings report both fit with headroom.
      maxTokens: MAX_REPORT_TOKENS,
      // High-effort thinking mode over a large token budget legitimately takes
      // a while; generous but still bounded so a stalled call can't hang a
      // scan in "analyzing" forever (see deepseekClient.ts). Raised alongside
      // maxTokens — a fuller response needs more wall-clock to stream.
      //
      // Sized from measurement, not guesswork: generation streams at roughly
      // 70 tokens/s, and a findings-heavy report spends ~13-15k tokens on
      // reasoning alone before the answer, so the old 120s cap could not fit a
      // real report — it only ever passed in testing because the cap wasn't
      // actually enforced over the body read (fixed in deepseekClient.ts), and
      // production instead died on undici's 300s socket timeout as `terminated`.
      timeoutMs: 300000,
    }, effectiveKey);
    if (!bodyTextRaw) {
      // The model produced no answer. This returned the local summary SILENTLY,
      // which made the degrade invisible: the scan shipped a fallback report and
      // the logs showed nothing at all, so "the AI report isn't working" could not
      // be confirmed or ruled out from the outside. The sibling catch below always
      // logged; this path never did, and it is the one that fires when the call
      // itself succeeded but came back empty.
      //
      // finish_reason is what distinguishes the causes: 'length' means reasoning
      // consumed the whole budget before any JSON was emitted (the failure mode
      // DeepSeekCallOptions warns about), anything else means the API returned an
      // empty completion for another reason.
      console.warn(
        `DeepSeek returned no report content, using high-quality local summary: ` +
        `finish_reason=${finishReason ?? 'unknown'} ` +
        `completion_tokens=${completionTokens ?? '?'}/${MAX_REPORT_TOKENS} ` +
        `reasoning_chars=${(reasoningContent || '').length}`,
      );
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
    // model now contributes only NARRATIVE prose — the executive summary, the
    // breakdown, and the per-finding fix prompt/impact merged by mergeModelProse
    // above; the findings panel and the score are fully reproducible.
    return {
      score: staticCompiled.score,
      severity: staticCompiled.severity,
      findings: mergeModelProse(staticCompiled.findings, data.findings),
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
