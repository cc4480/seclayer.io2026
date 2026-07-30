# @seclayer/mcp

A [Model Context Protocol](https://modelcontextprotocol.io) stdio server for [Seclayer](https://seclayer.io) — run a live black-box security scan directly from Claude Code, Cursor, Windsurf, or any other MCP-compatible AI agent. Exposes three tools: `seclayer_scan` (run a scan), `seclayer_list_scans` (review history), and `seclayer_get_report` (fetch a past report by id).

## Setup

This is a standard **stdio** MCP server — it speaks the Model Context Protocol
over stdin/stdout and does nothing client-specific, so it works in **any
MCP-compatible coding CLI or editor** (Claude Code, OpenAI Codex, Cursor,
Windsurf, Gemini CLI, VS Code / Copilot, Cline, Zed, and others). The only thing
that differs between clients is *where* the config lives and its exact syntax —
the launch command is always the same:

```
npx -y @seclayer/mcp
```

**1. Get an API key.** Generate one from the Seclayer dashboard's **Developer API
Keys** panel (the raw key is shown once — copy it immediately).

**2. Provide the key one of two ways:**
- As an env var — **`SECLAYER_API_KEY`** (recommended: keeps the secret out of
  process listings and shell history), or
- As a flag — **`--key YOUR_API_KEY`**.

**3. Register the server** using whichever config your client uses below.

### Generic config (Claude Code, Cursor, Windsurf, Cline, Gemini CLI, …)

Most clients read a JSON file with an `mcpServers` object. Add:

```json
{
  "mcpServers": {
    "seclayer": {
      "command": "npx",
      "args": ["-y", "@seclayer/mcp"],
      "env": { "SECLAYER_API_KEY": "YOUR_API_KEY" }
    }
  }
}
```

Where that JSON lives per client:

| Client | Config location |
|---|---|
| Claude Code | project `.mcp.json`, or run the CLI command below |
| Cursor | `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global) |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Gemini CLI | `~/.gemini/settings.json` |
| Cline | `cline_mcp_settings.json` (via the extension's MCP settings) |

### Claude Code (CLI)

```
claude mcp add seclayer --env SECLAYER_API_KEY=YOUR_API_KEY -- npx -y @seclayer/mcp
```

### OpenAI Codex CLI

Codex uses TOML, not JSON. Add to `~/.codex/config.toml`:

```toml
[mcp_servers.seclayer]
command = "npx"
args = ["-y", "@seclayer/mcp"]
env = { SECLAYER_API_KEY = "YOUR_API_KEY" }
```

### VS Code (GitHub Copilot / native MCP)

VS Code uses a `servers` key (not `mcpServers`) with an explicit `type`. Add to
`.vscode/mcp.json`:

```json
{
  "servers": {
    "seclayer": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@seclayer/mcp"],
      "env": { "SECLAYER_API_KEY": "YOUR_API_KEY" }
    }
  }
}
```

### Any other MCP client

If your client isn't listed, configure a **stdio / `command`-type** server with
command `npx` and args `["-y", "@seclayer/mcp"]`, and supply the API key via the
`SECLAYER_API_KEY` environment variable (or a `--key YOUR_API_KEY` arg). That's
all this server needs.

## Configuration

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--key` / `-k` | `SECLAYER_API_KEY` | *(required)* | Your Seclayer API key. |
| `--url` / `-u` | `SECLAYER_API_URL` | `https://seclayer.io` | Backend base URL — override for local/self-hosted testing. |

A flag always takes precedence over its corresponding environment variable. If no key is available from either source, the server prints an error to stderr and exits immediately rather than starting.

## Tools

The API key is never a tool parameter — it's bound once at server startup so it's never placed in the calling model's per-call context. All three tools use it automatically.

### `seclayer_scan` — run a new scan (costs one credit)

**Input:**
- `url` (required) — the target to scan, including scheme.
- `authHeader` (optional) — a raw `Authorization` header value (e.g. `Bearer eyJ...`) applied to every request, for scanning authenticated endpoints.

**Output:** a single Markdown report — posture score, severity, executive summary, and every finding with its OWASP category, business impact, and a ready-to-apply fix (plus a suggested prompt for whichever coding agent is calling the tool). Each call costs one credit from the account tied to the configured API key. Active exploit probing (SQLi/XSS/SSRF/etc.) only runs once that account has verified ownership of the target domain from the dashboard — otherwise the scan is passive recon only.

### `seclayer_list_scans` — review scan history (free, read-only)

**Input:** `limit` (optional, default 20, max 100).

**Output:** a Markdown table of the recent scans run under this API key — newest first, each with its scan id, target, status, posture score, and severity. Never launches a scan and costs no credits. Use it to recall a previous result, check whether a scan has finished, or find the id of a scan to fetch in full.

### `seclayer_get_report` — fetch a past report by id (free, read-only)

**Input:** `scanId` (required) — the id of a completed scan (from `seclayer_list_scans`).

**Output:** the same full Markdown report as `seclayer_scan` — for a scan that already ran, WITHOUT re-running or re-paying for it. Lets an agent act on a result it (or a teammate on the same key) already produced instead of scanning again.

## CI/CD gate (`seclayer-mcp scan`)

The same package doubles as a CI gate: run one scan and fail the build when any
active finding is at or above a severity threshold.

```bash
SECLAYER_API_KEY=... npx -y @seclayer/mcp scan \
  --url https://staging.example.com \
  --fail-on high
```

Options: `--url` (required), `--key` (or `SECLAYER_API_KEY`), `--api-url` (or
`SECLAYER_API_URL`, default `https://seclayer.io`), `--fail-on`
(`info|low|medium|high|critical`, default `high`), `--auth-header`. Exit codes:
**0** passed, **1** gate failed (findings at/above the threshold, listed on
stderr), **2** usage or scan error. Suppressed (false-positive) findings never
gate a build.

### GitHub Action

A composite action ships at `.github/actions/seclayer-scan`:

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: cc4480/seclayer.io2026/.github/actions/seclayer-scan@main
        with:
          url: https://staging.example.com
          api-key: ${{ secrets.SECLAYER_API_KEY }}
          fail-on: high
```

## Development

```bash
npm install        # from the repo root — this package is an npm workspace
npm run build -w @seclayer/mcp
npm test -w @seclayer/mcp
```

To exercise the server interactively against a local Seclayer instance:

```bash
npx @modelcontextprotocol/inspector node mcp-server/dist/index.js --key <key> --url http://localhost:3000
```

## Publishing a release

Publishing is automated by `.github/workflows/publish-mcp.yml`.

**One-time setup:** create an npm **Automation** access token (npmjs.com → Access
Tokens) for an account with publish rights to the `@seclayer` scope, and add it
as the `NPM_TOKEN` repository secret in GitHub.

**Cut a release:**

1. Bump the version in `mcp-server/package.json` (e.g. `0.1.0` → `0.1.1`).
2. Commit, then tag it to match: `git tag mcp-v0.1.1 && git push origin mcp-v0.1.1`.
   The workflow verifies the tag equals the package version, runs typecheck +
   tests + build, and publishes.

You can also trigger it manually from the **Actions** tab — leave `dry_run`
checked to validate the publish without releasing.

**Publishing manually instead** (from a machine logged in with `npm login`):

```bash
npm run build -w @seclayer/mcp
npm publish -w @seclayer/mcp --access public
```
