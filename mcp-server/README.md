# @seclayer/mcp

A [Model Context Protocol](https://modelcontextprotocol.io) stdio server for [Seclayer](https://seclayer.app) — run a live black-box security scan directly from Claude Code, Cursor, Windsurf, or any other MCP-compatible AI agent. Exposes three tools: `seclayer_scan` (run a scan), `seclayer_list_scans` (review history), and `seclayer_get_report` (fetch a past report by id).

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

### Windows: if the server fails to connect

On Windows the documented `npx` command frequently fails, in one of three ways.
All three are launcher problems, not package problems — the server itself
answers `initialize` in about a second.

| Symptom | Cause |
|---|---|
| Connection **times out** on first run | `npx` has to download the package before the server starts, which alone can exceed a client's 30-second startup timeout |
| **`CONNECTION_CLOSED`** | `npx` is a `.cmd` shim, so the client spawns `cmd` → `npx` → `node`; the extra process layers break the stdio pipe the protocol runs over |
| Works in `claude mcp list`, **times out at session startup** | the config used the bare command `node`. The health check inherits your shell's `PATH`, but the client spawns servers with a different environment, where `node` may not resolve |

The fix for all three is the same: install the package once, then give the
client **absolute paths for both the interpreter and the script**, so nothing
depends on `PATH` or a shim.

```
npm install -g @seclayer/mcp
```

Print both absolute paths:

```
node -e "console.log(process.execPath); console.log(require('path').join(require('child_process').execSync('npm root -g').toString().trim(),'@seclayer','mcp','dist','index.js'))"
```

That prints your `node.exe` path first and the installed server path second. Use
them as `command` and the first argument respectively.

Claude Code:

```
claude mcp add seclayer --env SECLAYER_API_KEY=YOUR_API_KEY -- "C:\full\path\to\node.exe" "C:\full\path\to\@seclayer\mcp\dist\index.js"
```

Or in JSON config (note the doubled backslashes — JSON escapes them):

```json
{
  "mcpServers": {
    "seclayer": {
      "command": "C:\\full\\path\\to\\node.exe",
      "args": ["C:\\full\\path\\to\\@seclayer\\mcp\\dist\\index.js"],
      "env": { "SECLAYER_API_KEY": "YOUR_API_KEY" }
    }
  }
}
```

This runs the same published package — it only removes the shim and `PATH`
layers. Restart your client afterwards: MCP servers are loaded at session
startup, so a newly added server won't appear in a session that is already
running.

macOS and Linux are unaffected; `npx -y @seclayer/mcp` works there as documented
above.

## Configuration

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--key` / `-k` | `SECLAYER_API_KEY` | *(required)* | Your Seclayer API key. |
| `--url` / `-u` | `SECLAYER_API_URL` | `https://seclayer.app` | Backend base URL — override for local/self-hosted testing. |

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
`SECLAYER_API_URL`, default `https://seclayer.app`), `--fail-on`
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

## Auto-fix PRs (`seclayer-mcp autofix`)

Closes the loop past just gating a build: scans a target, then for each
finding that's **proven or high-confidence** (never a medium/low-confidence
guess — see below), runs a DeepSeek-backed fix agent and opens a pull request
with the change.

```bash
SECLAYER_API_KEY=... npx -y @seclayer/mcp autofix \
  --url https://staging.example.com \
  --fail-on high \
  --max-fixes 3 \
  --test-cmd "npm test"
```

Options: everything `scan` (the CI gate) takes, plus `--max-fixes` (default
3), `--test-cmd` (optional — lets the agent run your test suite to check its
own work), and `--base-branch` (defaults to the workflow's own ref). Add
`--dry-run` to print which findings are eligible and preview the plan without
spending a credit or touching git. Requires `git` and the GitHub CLI (`gh`,
authenticated via `GH_TOKEN`/`GITHUB_TOKEN`) on `PATH`.

**What it does and doesn't do:**
- **No new secret required.** The fix agent is DeepSeek, proxied through the
  same Seclayer backend and billed through the same `SECLAYER_API_KEY` credits
  as every other MCP call — there's no separate AI key to provision.
- **Seclayer's servers never receive your source.** The backend only ever
  exchanges a message transcript and tool-call results; every file read, file
  edit, and test run happens locally, inside your own CI job.
- **Only proven/high-confidence findings qualify.** A finding is eligible only
  when it's not suppressed, is at or above `--fail-on`, and either carries a
  replayable exploit receipt or a `high` confidence rating — this ties
  directly into the product's low-false-positive design, so a run never burns
  a credit and a PR review cycle chasing a guess.
- **Always a PR, never a merge.** One branch and one pull request per finding
  (capped by `--max-fixes`), independently reviewable and revertable. Nothing
  is ever auto-merged.
- **A minimal, non-shell tool surface.** The agent can read files, edit files,
  and (only if you configure `--test-cmd`) run exactly that one fixed command
  — never an arbitrary shell. This matters because some finding data
  originates from the scanned target's own HTTP responses, so the tool
  surface is deliberately narrow enough that even a hostile target can't turn
  a scan into code execution beyond an in-repo file edit.

### GitHub Action

A composite action ships at `.github/actions/seclayer-autofix`. It needs
`contents: write` and `pull-requests: write`, so it's a separate opt-in action
from the read-only scan gate above:

```yaml
permissions:
  contents: write
  pull-requests: write

jobs:
  autofix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cc4480/seclayer.io2026/.github/actions/seclayer-autofix@main
        with:
          url: https://staging.example.com
          api-key: ${{ secrets.SECLAYER_API_KEY }}
          fail-on: high
          max-fixes: 3
          test-command: npm test
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
