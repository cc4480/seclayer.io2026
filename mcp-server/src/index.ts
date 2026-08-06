#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { parseArgs, resolveConfig } from "./cli.js";
import { buildServer } from "./server.js";
import { runCiScan } from "./ciScan.js";
import { runAutofix } from "./autofix.js";
import { VERSION } from "./version.js";

const HELP_TEXT = `seclayer-mcp — Model Context Protocol server for Seclayer security scans.

Usage:
  seclayer-mcp --key <API_KEY> [--url <BASE_URL>]

Options:
  -k, --key <key>    Seclayer API key (required). Also read from SECLAYER_API_KEY.
  -u, --url <url>    Backend base URL (default: https://seclayer.io). Also read from SECLAYER_API_URL.
  -h, --help         Show this help and exit.
  -v, --version      Show the version and exit.

Generate an API key from the Seclayer dashboard's Developer API Keys panel, then add this
server to your MCP client (Claude Code, Cursor, Windsurf) as a stdio "command" server:
  npx -y @seclayer/mcp --key YOUR_API_KEY
`;

async function main() {
  // `seclayer-mcp scan ...` is the CI/CD gate: run one scan and exit non-zero on
  // findings at/above a threshold. `seclayer-mcp autofix ...` runs a scan and
  // opens a PR per eligible finding. With no subcommand, run the MCP stdio server.
  if (process.argv[2] === "scan") {
    const code = await runCiScan(process.argv.slice(3), process.env);
    process.exit(code);
  }
  if (process.argv[2] === "autofix") {
    const code = await runAutofix(process.argv.slice(3), process.env);
    process.exit(code);
  }

  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    process.stdout.write(HELP_TEXT);
    process.exit(0);
  }
  if (args.version) {
    process.stdout.write(`${VERSION}\n`);
    process.exit(0);
  }

  const result = resolveConfig(args, process.env);
  if (!result.ok) {
    // stderr, never stdout — stdout is the JSON-RPC channel once the
    // transport connects, and must never carry anything else.
    process.stderr.write(`[seclayer-mcp] ${result.error}\n`);
    process.exit(1);
  }

  const server = buildServer(result.config);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  process.stderr.write(`[seclayer-mcp] Fatal error: ${err?.message || err}\n`);
  process.exit(1);
});
