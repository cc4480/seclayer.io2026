// `seclayer-mcp autofix` — runs a scan, then for each proven/high-confidence
// finding at or above a severity threshold, drives a DeepSeek-backed agent
// loop (proxied through the Seclayer backend — see server/routes/autofix.ts)
// that reads/edits files and opens a pull request with the fix. Everything
// that touches the filesystem happens locally via autofixTools.ts; the
// backend only ever sees the message transcript and tool-call results, never
// the repository itself. Separate from ciScan.ts (the build-gate subcommand)
// on purpose — autofix never fails the build, it's purely additive.
import { randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { scan } from "./client.js";
import { startAutofixSession, autofixTurn } from "./client.js";
import { readFile, listDir, editFile, runTestCommand } from "./autofixTools.js";
import type { AgentMessage, AgentToolCall, Finding, Severity } from "./types.js";

const RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

// A client-side backstop matching the server's own MAX_TURNS — bounds a run
// even if the server's cap signal is ever missed.
const MAX_TURNS = 25;

export interface AutofixArgs {
  url?: string;
  apiKey?: string;
  apiUrl: string;
  failOn: string;
  authHeader?: string;
  maxFixes: number;
  testCmd?: string;
  baseBranch?: string;
  dryRun: boolean;
  help?: boolean;
}

export const AUTOFIX_HELP = `seclayer-mcp autofix — scan a target and open a PR fixing each proven finding.

Usage:
  seclayer-mcp autofix --url <target> [options]

Options:
  -u, --url <url>          Target to scan, including scheme (required).
  -k, --key <key>          Seclayer API key (or env SECLAYER_API_KEY).
      --api-url <url>      Backend base URL (default https://seclayer.app, or env SECLAYER_API_URL).
      --fail-on <sev>      Minimum severity eligible for auto-fix: info|low|medium|high|critical (default high).
      --max-fixes <n>      Maximum number of findings to attempt in one run (default 3).
      --test-cmd <cmd>     Command the agent may run to check its own work (e.g. "npm test"). Optional.
      --base-branch <name> Branch name PRs are opened against (default: autodetected from GITHUB_HEAD_REF/GITHUB_REF_NAME, or "main").
      --auth-header <v>    Optional Authorization header value for authenticated targets.
      --dry-run             Print the plan (eligible findings, prompts) without spending credits or touching git.
  -h, --help                Show this help.

Only findings that are NOT suppressed, at or above --fail-on, AND either
confidence:"high" or carrying replayable exploit evidence are eligible — this
never spends a credit chasing a low-confidence guess. Each eligible finding
gets its own branch and its own pull request; nothing is ever merged
automatically. Requires "git" and the GitHub CLI ("gh", authenticated via
GH_TOKEN/GITHUB_TOKEN in the environment) to be available on PATH.

Exit codes: 0 = ran (see the per-finding summary for outcomes), 2 = usage or scan error.`;

export function parseAutofixArgs(argv: string[], env: NodeJS.ProcessEnv): AutofixArgs {
  const a: AutofixArgs = {
    apiUrl: env.SECLAYER_API_URL || "https://seclayer.app",
    failOn: "high",
    apiKey: env.SECLAYER_API_KEY,
    maxFixes: 3,
    dryRun: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const v = argv[i];
    if (v === "--url" || v === "-u") a.url = argv[++i];
    else if (v === "--key" || v === "-k") a.apiKey = argv[++i];
    else if (v === "--api-url") a.apiUrl = argv[++i];
    else if (v === "--fail-on") a.failOn = (argv[++i] || "").toLowerCase();
    else if (v === "--max-fixes") a.maxFixes = Math.max(1, Number(argv[++i]) || 3);
    else if (v === "--test-cmd") a.testCmd = argv[++i];
    else if (v === "--base-branch") a.baseBranch = argv[++i];
    else if (v === "--auth-header") a.authHeader = argv[++i];
    else if (v === "--dry-run") a.dryRun = true;
    else if (v === "--help" || v === "-h") a.help = true;
  }
  return a;
}

// Pure: which findings qualify for an auto-fix attempt, severity-sorted
// (most severe first). Mirrors ciScan.ts's blockingFindings but adds the
// confidence/evidence gate — never spend a credit and a PR review cycle
// chasing a medium/low-confidence guess.
export function autofixEligible(findings: Finding[], failOn: Severity): Finding[] {
  const min = RANK[failOn];
  return (findings || [])
    .filter((f) => !f.isFalsePositive && RANK[f.severity] >= min && (f.confidence === "high" || f.evidence != null))
    .sort((a, b) => RANK[b.severity] - RANK[a.severity]);
}

export function slugify(title: string): string {
  return title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-+|-+$)/g, "").slice(0, 40) || "finding";
}

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function ghCli(args: string[], cwd: string): string {
  return execFileSync("gh", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

// A base branch NAME is only ever used as the --base for `gh pr create` — the
// actual git checkout below always branches from the exact commit SHA
// actions/checkout left us on, which works whether that checkout is a named
// branch or (the common case for pull_request-triggered runs) detached HEAD.
export function resolveBaseBranchName(explicit: string | undefined, env: NodeJS.ProcessEnv): string {
  return explicit || env.GITHUB_HEAD_REF || env.GITHUB_REF_NAME || "main";
}

interface FixOutcome {
  finding: Finding;
  status: "opened" | "no-change" | "error" | "dry-run";
  detail: string;
}

async function executeTool(call: AgentToolCall, repoRoot: string, testCmd: string | undefined): Promise<string> {
  let args: any = {};
  try {
    args = JSON.parse(call.function.arguments || "{}");
  } catch {
    return `Could not parse arguments for "${call.function.name}" as JSON.`;
  }

  switch (call.function.name) {
    case "read_file":
      return (await readFile(repoRoot, args.path)).output;
    case "list_dir":
      return (await listDir(repoRoot, args.path ?? ".")).output;
    case "edit_file":
      return (await editFile(repoRoot, args.path, args.old_string, args.new_string)).output;
    case "run_test_command":
      return runTestCommand(repoRoot, testCmd).output;
    case "done":
      return "Acknowledged.";
    default:
      return `Unknown tool "${call.function.name}" — no action taken.`;
  }
}

export function buildPrBody(finding: Finding, agentSummary: string, targetUrl: string): string {
  const lines: string[] = [
    `Opened automatically by **Seclayer auto-fix** after a scan of \`${targetUrl}\` confirmed this finding.`,
    "",
    `**Finding:** ${finding.title}`,
    `**Severity:** ${finding.severity.toUpperCase()}${finding.confidence ? ` · confidence: ${finding.confidence}` : ""}`,
  ];
  if (finding.owasp) lines.push(`**OWASP:** ${finding.owasp}`);
  lines.push("", finding.description);
  if (finding.impact) lines.push("", `**Impact:** ${finding.impact}`);
  lines.push("", "**What the fix agent did:**", agentSummary || "(no summary provided)");
  lines.push(
    "",
    "---",
    "This PR was generated by an AI agent acting on a Seclayer scan finding — review it like any other contribution before merging. Seclayer's servers never received this repository's source; the fix ran entirely inside this CI job.",
  );
  return lines.join("\n");
}

async function runOneFinding(
  finding: Finding,
  opts: { apiUrl: string; apiKey: string; url: string; startSha: string; baseBranchName: string; testCmd?: string; repoRoot: string },
  out: (s: string) => void,
): Promise<FixOutcome> {
  const branch = `seclayer/autofix/${slugify(finding.title)}-${randomBytes(3).toString("hex")}`;

  const started = await startAutofixSession(opts.apiUrl, opts.apiKey, {
    url: opts.url,
    findingTitle: finding.title,
    findingCategory: finding.category,
  });
  if (!started.ok) return { finding, status: "error", detail: started.message };

  try {
    git(["checkout", "-b", branch, opts.startSha], opts.repoRoot);
  } catch (err: any) {
    return { finding, status: "error", detail: `Could not create branch "${branch}": ${err?.message || err}` };
  }

  const systemPrompt = [
    "You are an autonomous security-fix agent running inside this repository's own CI job.",
    "You have exactly these tools: read_file, list_dir, edit_file" +
      (opts.testCmd ? ", and run_test_command" : " (no test command is configured for this run)") + ".",
    "There is no shell access beyond that, and no way to run arbitrary commands.",
    "Work the single finding below to completion, then call the `done` tool with a short summary.",
    "If the finding does not actually apply to this codebase, say so honestly in `done` rather than inventing a change.",
    "Keep the diff minimal and focused on this one issue.",
  ].join(" ");

  const messages: AgentMessage[] = [
    { role: "system", content: systemPrompt },
    { role: "user", content: finding.agentPrompt || `${finding.title}\n\n${finding.description}\n\nFix: ${finding.fix}` },
  ];

  let sessionDone = false;
  let doneSummary = "";
  for (let turn = 0; turn < MAX_TURNS && !sessionDone; turn++) {
    const res = await autofixTurn(opts.apiUrl, opts.apiKey, started.sessionId, messages);
    if (!res.ok) {
      git(["checkout", opts.startSha], opts.repoRoot);
      return { finding, status: "error", detail: res.message };
    }

    messages.push({
      role: "assistant",
      content: res.content ?? "",
      tool_calls: res.toolCalls.length ? res.toolCalls : undefined,
    });

    if (res.toolCalls.length === 0) {
      messages.push({ role: "user", content: "Continue by calling one of your tools, or call `done` if you're finished." });
    } else {
      for (const call of res.toolCalls) {
        const output = await executeTool(call, opts.repoRoot, opts.testCmd);
        if (call.function.name === "done") {
          try {
            doneSummary = JSON.parse(call.function.arguments || "{}").summary || "";
          } catch {
            doneSummary = "(agent called done without a parseable summary)";
          }
        }
        messages.push({ role: "tool", tool_call_id: call.id, content: output });
      }
    }

    if (res.sessionDone) sessionDone = true;
  }

  const dirty = git(["status", "--porcelain"], opts.repoRoot);
  if (!dirty) {
    git(["checkout", opts.startSha], opts.repoRoot);
    try { git(["branch", "-D", branch], opts.repoRoot); } catch { /* best-effort cleanup */ }
    return { finding, status: "no-change", detail: doneSummary || "The agent made no file changes." };
  }

  git(["add", "-A"], opts.repoRoot);
  git(["commit", "-m", `Seclayer autofix: ${finding.title}`], opts.repoRoot);
  git(["push", "-u", "origin", branch], opts.repoRoot);

  let prUrl: string;
  try {
    prUrl = ghCli(
      ["pr", "create", "--title", `Seclayer autofix: ${finding.title}`, "--body", buildPrBody(finding, doneSummary, opts.url), "--base", opts.baseBranchName, "--head", branch],
      opts.repoRoot,
    );
  } catch (err: any) {
    git(["checkout", opts.startSha], opts.repoRoot);
    return { finding, status: "error", detail: `Fix committed on branch "${branch}" but PR creation failed: ${err?.message || err}` };
  }

  git(["checkout", opts.startSha], opts.repoRoot);
  return { finding, status: "opened", detail: prUrl };
}

export async function runAutofix(
  argv: string[],
  env: NodeJS.ProcessEnv,
  out: (s: string) => void = console.log,
  err: (s: string) => void = console.error,
): Promise<number> {
  const args = parseAutofixArgs(argv, env);
  if (args.help) { out(AUTOFIX_HELP); return 0; }
  if (!args.url) { err("error: --url is required. See `seclayer-mcp autofix --help`."); return 2; }
  if (!args.apiKey) { err("error: an API key is required (--key or SECLAYER_API_KEY)."); return 2; }
  if (!(args.failOn in RANK)) {
    err(`error: --fail-on must be one of: ${Object.keys(RANK).join(", ")}. Got "${args.failOn}".`);
    return 2;
  }

  out(`Seclayer autofix → ${args.url}  (fail-on: ${args.failOn}, max-fixes: ${args.maxFixes})`);
  const outcome = await scan(args.apiUrl, args.apiKey, { url: args.url, authHeader: args.authHeader });
  if (!outcome.ok) {
    err(`Scan error: ${outcome.message}`);
    return 2;
  }

  const eligible = autofixEligible(outcome.data.securityFindings, args.failOn as Severity).slice(0, args.maxFixes);
  out(`Findings: ${outcome.data.securityFindings.length} total; ${eligible.length} eligible for auto-fix (proven/high-confidence, at or above ${args.failOn}).`);
  if (eligible.length === 0) {
    out("Nothing eligible — no auto-fix PRs to open.");
    return 0;
  }

  const repoRoot = process.cwd();
  const baseBranchName = resolveBaseBranchName(args.baseBranch, env);

  if (args.dryRun) {
    out(`\nDry run — no credits spent, no git/PR actions taken. Base branch for PRs would be "${baseBranchName}".\n`);
    for (const f of eligible) {
      out(`  [${f.severity.toUpperCase()}] ${f.title}`);
      out(`    would branch: seclayer/autofix/${slugify(f.title)}-<random>`);
      out(`    prompt preview: ${(f.agentPrompt || f.description).split("\n")[0].slice(0, 100)}…`);
    }
    return 0;
  }

  let startSha: string;
  try {
    startSha = git(["rev-parse", "HEAD"], repoRoot);
  } catch (e: any) {
    err(`error: could not resolve the current git commit (${e?.message || e}). Is this running inside a git checkout?`);
    return 2;
  }

  const results: FixOutcome[] = [];
  for (const finding of eligible) {
    out(`\n→ ${finding.title} [${finding.severity.toUpperCase()}]`);
    const result = await runOneFinding(finding, {
      apiUrl: args.apiUrl,
      apiKey: args.apiKey,
      url: args.url,
      startSha,
      baseBranchName,
      testCmd: args.testCmd,
      repoRoot,
    }, out);
    results.push(result);
    if (result.status === "opened") out(`  ✓ PR opened: ${result.detail}`);
    else if (result.status === "no-change") out(`  – skipped (no changes): ${result.detail}`);
    else out(`  ✗ error: ${result.detail}`);
  }

  out(`\nSummary: ${results.filter((r) => r.status === "opened").length} PR(s) opened, ` +
    `${results.filter((r) => r.status === "no-change").length} skipped, ` +
    `${results.filter((r) => r.status === "error").length} failed, out of ${results.length} attempted.`);

  return 0;
}
