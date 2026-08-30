// CI/CD gate. `seclayer-mcp scan --url <target> --fail-on <severity>` runs one
// scan through the same backend the MCP tool uses and exits non-zero when any
// active finding is at or above the threshold — so a pipeline can block a deploy
// on new vulnerabilities. Separate from the stdio MCP server (index.ts) so the
// CLI and the agent tool don't entangle; reuses client.scan().
import { scan } from "./client.js";
import type { Finding, Severity } from "./types.js";

const RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export interface CiArgs {
  url?: string;
  apiKey?: string;
  apiUrl: string;
  failOn: string;
  authHeader?: string;
  help?: boolean;
}

export const CI_HELP = `seclayer-mcp scan — run a Seclayer scan in CI and gate the build on findings.

Usage:
  seclayer-mcp scan --url <target> [--fail-on <severity>] [--key <API_KEY>] [--api-url <BASE_URL>]

Options:
  -u, --url <url>         Target to scan, including scheme (required).
  -k, --key <key>         Seclayer API key (or env SECLAYER_API_KEY).
      --api-url <url>     Backend base URL (default https://seclayer.app, or env SECLAYER_API_URL).
      --fail-on <sev>     Minimum severity that fails the build: info|low|medium|high|critical (default high).
      --auth-header <v>   Optional Authorization header value for authenticated targets.
  -h, --help              Show this help.

Exit codes: 0 = passed (nothing at/above threshold), 1 = gate failed, 2 = usage/scan error.`;

export function parseCiArgs(argv: string[], env: NodeJS.ProcessEnv): CiArgs {
  const a: CiArgs = {
    apiUrl: env.SECLAYER_API_URL || "https://seclayer.app",
    failOn: "high",
    apiKey: env.SECLAYER_API_KEY,
  };
  for (let i = 0; i < argv.length; i++) {
    const v = argv[i];
    if (v === "--url" || v === "-u") a.url = argv[++i];
    else if (v === "--key" || v === "-k") a.apiKey = argv[++i];
    else if (v === "--api-url") a.apiUrl = argv[++i];
    else if (v === "--fail-on") a.failOn = (argv[++i] || "").toLowerCase();
    else if (v === "--auth-header") a.authHeader = argv[++i];
    else if (v === "--help" || v === "-h") a.help = true;
  }
  return a;
}

// Pure: the findings that meet or exceed the fail-on threshold (suppressed
// findings never gate a build). Isolated so the threshold logic is unit-tested
// without a network call.
export function blockingFindings(findings: Finding[], failOn: Severity): Finding[] {
  const min = RANK[failOn];
  return (findings || []).filter((f) => !f.isFalsePositive && RANK[f.severity] >= min);
}

// Runs the gate and returns a process exit code. IO is injected so it's testable.
export async function runCiScan(
  argv: string[],
  env: NodeJS.ProcessEnv,
  out: (s: string) => void = console.log,
  err: (s: string) => void = console.error,
): Promise<number> {
  const args = parseCiArgs(argv, env);
  if (args.help) { out(CI_HELP); return 0; }
  if (!args.url) { err("error: --url is required. See `seclayer-mcp scan --help`."); return 2; }
  if (!args.apiKey) { err("error: an API key is required (--key or SECLAYER_API_KEY)."); return 2; }
  if (!(args.failOn in RANK)) {
    err(`error: --fail-on must be one of: ${Object.keys(RANK).join(", ")}. Got "${args.failOn}".`);
    return 2;
  }

  out(`Seclayer scan → ${args.url}  (fail-on: ${args.failOn})`);
  const outcome = await scan(args.apiUrl, args.apiKey, { url: args.url, authHeader: args.authHeader });
  if (!outcome.ok) {
    err(`Scan error: ${outcome.message}`);
    return 2;
  }

  const data = outcome.data;
  out(`Posture score: ${data.postureScore}/100 (${data.vulnerabilityLevel.toUpperCase()})`);
  const blocking = blockingFindings(data.securityFindings, args.failOn as Severity);
  out(`Findings: ${data.securityFindings.length} total; ${blocking.length} at or above ${args.failOn}.`);

  if (blocking.length > 0) {
    err(`\n✗ Security gate FAILED — ${blocking.length} finding(s) at or above "${args.failOn}":`);
    for (const f of blocking) err(`  [${f.severity.toUpperCase()}] ${f.title}${f.owasp ? `  (${f.owasp})` : ""}`);
    err(`\nView the full report and fixes at ${args.apiUrl}.`);
    return 1;
  }
  out(`\n✓ Security gate PASSED — no findings at or above "${args.failOn}".`);
  return 0;
}
