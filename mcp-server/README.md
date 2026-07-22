# @seclayer/mcp

A [Model Context Protocol](https://modelcontextprotocol.io) stdio server for [Seclayer](https://seclayer.io) — run a live black-box security scan directly from Claude Code, Cursor, Windsurf, or any other MCP-compatible AI agent, via a single `seclayer_scan` tool.

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

## The `seclayer_scan` tool

**Input:**
- `url` (required) — the target to scan, including scheme.
- `authHeader` (optional) — a raw `Authorization` header value (e.g. `Bearer eyJ...`) applied to every request, for scanning authenticated endpoints.

The API key is never a tool parameter — it's bound once at server startup so it's never placed in the calling model's per-call context.

**Output:** a single Markdown report — posture score, severity, executive summary, and every finding with its OWASP category, business impact, and a ready-to-apply fix (plus a suggested prompt for whichever coding agent is calling the tool). Each call costs one credit from the account tied to the configured API key. Active exploit probing (SQLi/XSS/SSRF/etc.) only runs once that account has verified ownership of the target domain from the dashboard — otherwise the scan is passive recon only.

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
