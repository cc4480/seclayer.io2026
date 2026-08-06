// Executors for the fixed tool schema the autofix backend hands the model
// (see server/routes/autofix.ts's AUTOFIX_TOOLS in the main app — the tool
// names here must mirror it exactly). This file is the ONLY code in the
// autofix path that touches the filesystem or a shell, so every path argument
// is treated as untrusted (it ultimately originates from a model response,
// which can itself be influenced by content pulled from the scanned target)
// and resolved strictly inside repoRoot before any read/write happens.
import { promises as fs } from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";

export interface ToolResult {
  ok: boolean;
  output: string;
}

// Resolves a model-supplied, repo-relative path against repoRoot and throws
// if the result would land outside it (absolute paths, "../" escapes). This
// is the single highest-risk check in the whole autofix feature — a bug here
// turns a file-edit tool into an arbitrary-write primitive.
export function resolveInRepo(repoRoot: string, requested: string): string {
  const resolvedRoot = path.resolve(repoRoot);
  const resolved = path.resolve(resolvedRoot, requested);
  const withSep = resolvedRoot.endsWith(path.sep) ? resolvedRoot : resolvedRoot + path.sep;
  if (resolved !== resolvedRoot && !resolved.startsWith(withSep)) {
    throw new Error(`Path "${requested}" resolves outside the repository and was rejected.`);
  }
  return resolved;
}

// Caps how much of one file's content re-enters the model's context — a huge
// generated/vendored file would blow the turn budget for no benefit.
const MAX_READ_BYTES = 50_000;
const MAX_COMMAND_OUTPUT = 20_000;

export async function readFile(repoRoot: string, requested: string): Promise<ToolResult> {
  try {
    const full = resolveInRepo(repoRoot, requested);
    const content = await fs.readFile(full, "utf8");
    const truncated = content.length > MAX_READ_BYTES;
    return {
      ok: true,
      output: truncated ? `${content.slice(0, MAX_READ_BYTES)}\n…[truncated, ${content.length} bytes total]` : content,
    };
  } catch (err: any) {
    return { ok: false, output: `Could not read "${requested}": ${err?.message || err}` };
  }
}

export async function listDir(repoRoot: string, requested: string): Promise<ToolResult> {
  try {
    const full = resolveInRepo(repoRoot, requested || ".");
    const entries = await fs.readdir(full, { withFileTypes: true });
    const lines = entries
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((e) => `${e.isDirectory() ? "d" : "-"} ${e.name}`);
    return { ok: true, output: lines.length ? lines.join("\n") : "(empty directory)" };
  } catch (err: any) {
    return { ok: false, output: `Could not list "${requested}": ${err?.message || err}` };
  }
}

// Old-string/new-string replace, mirroring the coding-agent Edit-tool
// convention the rest of the product already writes prompts for (see
// server/agentPrompt.ts). Requires old_string to match EXACTLY ONE place in
// the file, so an ambiguous or stale match fails loudly instead of editing the
// wrong occurrence.
export async function editFile(
  repoRoot: string,
  requested: string,
  oldString: string,
  newString: string,
): Promise<ToolResult> {
  try {
    const full = resolveInRepo(repoRoot, requested);
    const content = await fs.readFile(full, "utf8");
    const occurrences = content.split(oldString).length - 1;
    if (occurrences === 0) {
      return {
        ok: false,
        output: `old_string was not found verbatim in "${requested}". Re-read the file and match its exact current content, including whitespace.`,
      };
    }
    if (occurrences > 1) {
      return {
        ok: false,
        output: `old_string matches ${occurrences} places in "${requested}"; it must be unique. Include more surrounding context.`,
      };
    }
    await fs.writeFile(full, content.replace(oldString, newString), "utf8");
    return { ok: true, output: `Updated "${requested}".` };
  } catch (err: any) {
    return { ok: false, output: `Could not edit "${requested}": ${err?.message || err}` };
  }
}

// Runs EXACTLY the operator-supplied command string — never anything derived
// from the model, since the run_test_command tool schema takes no parameters.
// A missing command is a documented no-op, not a silent success.
export function runTestCommand(repoRoot: string, testCommand: string | undefined): ToolResult {
  if (!testCommand) {
    return { ok: false, output: "No test command was configured for this run (--test-cmd was not set)." };
  }
  try {
    const output = execSync(testCommand, {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 5 * 60 * 1000,
    });
    return { ok: true, output: output.slice(0, MAX_COMMAND_OUTPUT) };
  } catch (err: any) {
    const combined = [err?.stdout, err?.stderr].filter(Boolean).join("\n") || err?.message || String(err);
    return { ok: false, output: combined.slice(0, MAX_COMMAND_OUTPUT) };
  }
}
