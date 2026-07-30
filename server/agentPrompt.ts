import { Finding, Severity } from "../src/types.js";

// Builds the "hand this to your AI coding agent" prompt for a finding — a single,
// structured, agent-agnostic MASTER PROMPT that behaves the same for any AI
// coding agent on any platform. Shared by the static compiler
// (server/findings.ts, used whenever DeepSeek is not configured or a given
// finding doesn't come back with its own prompt) and the DeepSeek report
// generator (server/deepseek.ts, which asks the model to write a sharper,
// finding-specific body but falls back to this).
//
// The scanner is black-box and never sees the user's source, so the prompt drives
// the agent from OBSERVED BEHAVIOR — what to search for, how to confirm the flaw
// is real, and how to verify the fix — rather than naming a file it cannot know.
// When a finding carries a replayable exploit receipt (evidence), that proof is
// folded in so the agent can reproduce the issue before touching code.
type AgentPromptInput = Pick<Finding, "title" | "description" | "fix" | "category" | "owasp"> &
  Partial<Pick<Finding, "severity" | "confidence" | "impact" | "endpoint" | "evidence">>;

export function buildAgentPrompt(finding: AgentPromptInput, targetUrl: string): string {
  const lines: string[] = [];

  // --- Role + task framing (kept provider-neutral so it ports across agents) ---
  lines.push(
    `# Security Fix Task — ${finding.title}`,
    "",
    "You are a senior application security engineer with full write access to this",
    "repository. Resolve ONE confirmed security issue end-to-end: find it, fix the",
    "root cause, and prove it's gone — without regressions or weakening any other",
    "control. This prompt is self-contained, provider-neutral, and portable: it",
    "works the same with any AI coding agent on any platform.",
    "",
  );

  // --- The issue: title, classification, where, and why it matters ---
  lines.push("## The issue", "", `- Finding: ${finding.title}`);
  const sevConf = [
    finding.severity ? `Severity: ${finding.severity.toUpperCase()}` : "",
    finding.confidence ? `confidence: ${finding.confidence}` : "",
  ].filter(Boolean).join(" · ");
  if (sevConf) lines.push(`- ${sevConf}`);
  const classification = [finding.category, finding.owasp ? `OWASP ${finding.owasp}` : ""]
    .filter(Boolean)
    .join(" · ");
  if (classification) lines.push(`- Classification: ${classification}`);
  lines.push(`- Scanned target (black-box): ${targetUrl}`);
  if (finding.endpoint) lines.push(`- Affected endpoint: ${finding.endpoint}`);
  lines.push("", finding.description);
  if (finding.impact) lines.push("", `Impact if left unfixed: ${finding.impact}`);

  // --- Proof (only when a real, replayable exploit receipt exists) ---
  const ev = finding.evidence;
  if (ev) {
    lines.push("", "## Proof this is real (not theoretical)", "");
    if (ev.demonstration) lines.push(ev.demonstration, "");
    if (ev.reproduction) {
      lines.push("Reproduce it yourself:", "", "```", ev.reproduction, "```");
    }
    if (ev.signal?.quote) {
      lines.push(
        "",
        `Observed signal that confirms it: ${JSON.stringify(ev.signal.quote)}`,
      );
      if (ev.signal.why) lines.push(`Why that proves it: ${ev.signal.why}`);
    }
  }

  // --- The recommended fix ---
  lines.push("", "## Recommended fix", "", finding.fix);

  // --- The workflow: a strict, verifiable order every agent can follow ---
  lines.push(
    "",
    "## Work it in this order",
    "1. Locate — this scan is black-box and never read your source, so start from",
    "   the behavior/endpoint above and search the codebase for the route, handler,",
    "   or config that produces it. State the file(s) you believe are responsible.",
    "2. Confirm — reproduce the issue locally before changing anything. If it does",
    "   NOT actually apply here, stop and report it as a likely false positive with",
    "   your reasoning. Never invent a change just to satisfy this prompt.",
    "3. Fix the root cause — apply the recommended fix using this project's existing",
    "   stack, libraries, and conventions. Make the smallest change that fully closes",
    "   the issue, and if the same flaw pattern repeats elsewhere, fix every instance.",
    "4. Add a regression test — one that FAILS on the vulnerable code and PASSES",
    "   after the fix, in the project's existing test framework and layout.",
    "5. Verify — run the full test suite and re-exercise the affected request.",
    "   Confirm the issue is resolved and nothing else broke.",
  );

  // --- Guardrails: what NOT to do ---
  lines.push(
    "",
    "## Guardrails",
    "- Do not disable, bypass, or loosen any other security control (auth, CORS,",
    "  CSP, input validation) to make this pass.",
    "- Keep the diff minimal and reviewable; do not refactor unrelated code.",
    "- Never hardcode secrets or credentials. If a dependency upgrade is required,",
    "  pin the patched version and call out any breaking changes.",
    "- If a safe fix isn't possible without broader changes, stop and explain",
    "  rather than guessing.",
  );

  // --- Definition of done: an explicit, checkable acceptance list ---
  lines.push(
    "",
    "## Done when",
    "- [ ] Root cause fixed (not just this one symptom/endpoint if the pattern repeats).",
    "- [ ] Regression test added and passing.",
    "- [ ] Full test suite still green.",
    "- [ ] You've summarized what changed, which files, and how you verified it.",
  );

  return lines.join("\n");
}

// Local (non-AI) fallback for the plain-English "if exploited, then..." line.
// DeepSeek is asked to write a sharper, finding-specific version of this.
const IMPACT_BY_SEVERITY: Record<Severity, string> = {
  critical: "If exploited, this typically leads to full compromise: data exfiltration, account takeover, or remote code execution.",
  high: "If exploited, this can expose sensitive data or grant an attacker unauthorized access or control.",
  medium: "If exploited, this weakens the site's defenses and can be chained with other issues to greater effect.",
  low: "Low direct risk on its own, but it removes a defensive layer and is worth closing.",
  info: "Informational — no direct exploit risk, included for completeness.",
};

export function buildImpactFallback(severity: Severity): string {
  return IMPACT_BY_SEVERITY[severity] ?? IMPACT_BY_SEVERITY.info;
}
