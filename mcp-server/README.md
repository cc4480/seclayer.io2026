# @seclayer/mcp

A [Model Context Protocol](https://modelcontextprotocol.io) stdio server for [Seclayer](https://seclayer.io) — run a live black-box security scan directly from Claude Code, Cursor, Windsurf, or any other MCP-compatible AI agent. Exposes three tools: `seclayer_scan` (run a scan), `seclayer_list_scans` (review history), and `seclayer_get_report` (fetch a past report by id).

## Setup

1. Generate an API key from the Seclayer dashboard's **Developer API Keys** panel (the raw key is shown once — copy it immediately).
2. Add this server to your MCP client as a `command`-type stdio server:

```
npx -y @seclayer/mcp --key YOUR_API_KEY
```

### Claude Code

```
claude mcp add seclayer -- npx -y @seclayer/mcp --key YOUR_API_KEY
```

### Cursor

Settings → Features → MCP → Add New Server:

| Field | Value |
|---|---|
| Name | `seclayer` |
| Type | `command` |
| Command | `npx -y @seclayer/mcp --key YOUR_API_KEY` |

### Windsurf

Same `command`-type stdio configuration as Cursor, using the same `npx -y @seclayer/mcp --key YOUR_API_KEY` command.

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
