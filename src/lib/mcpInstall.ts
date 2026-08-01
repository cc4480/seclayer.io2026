// One-click install artifacts for the Seclayer MCP server.
//
// The single biggest onboarding wall is hand-editing a client's JSON config to
// register the stdio server. This module builds every "just click it" install
// path — editor deeplinks (Cursor, VS Code) and copy-paste configs/commands —
// from one place, so a freshly generated API key can be embedded into a working
// install with zero file editing.
//
// Everything here is pure and framework-free (no DOM, no React) so the URL/JSON
// assembly is unit-tested directly. The stdio launch command is identical in
// every client — only where the config lives and its exact shape differ — so a
// single server config drives all of them.

export const MCP_PACKAGE = '@seclayer/mcp';
export const MCP_SERVER_NAME = 'seclayer';

// Mirrors the mcp-server CLI default (mcp-server/src/cli.ts). A base URL equal to
// this is left out of the config entirely — the published package already
// defaults to it, so emitting SECLAYER_API_URL would be noise.
const DEFAULT_BASE_URL = 'https://seclayer.io';

// Shown when no real key is available yet (the raw key is only in hand right
// after generation). Deeplinks built with this are copy-paste templates, not
// one-click installs — callers gate the live buttons on having a real key.
export const PLACEHOLDER_KEY = 'YOUR_API_KEY';

export interface McpInstallOptions {
  // The raw API key to embed. When absent/empty a placeholder is used so the
  // generated config is still a valid, copy-paste-ready template.
  apiKey?: string | null;
  // Backend base URL. Only emitted (as SECLAYER_API_URL / --url) when it differs
  // from the package default, so production installs stay clean while a local or
  // self-hosted dashboard points the server back at itself.
  baseUrl?: string;
}

function normalizeBaseUrl(url?: string): string {
  if (!url) return DEFAULT_BASE_URL;
  return url.replace(/\/+$/, '');
}

// True when a non-default backend URL should be threaded through the install.
function customBaseUrl(opts: McpInstallOptions): string | null {
  const base = normalizeBaseUrl(opts.baseUrl);
  return base && base !== DEFAULT_BASE_URL ? base : null;
}

function keyOrPlaceholder(opts: McpInstallOptions): string {
  return opts.apiKey?.trim() || PLACEHOLDER_KEY;
}

// The stdio server entry every MCP client understands: the value that sits under
// the server's name in an `mcpServers` map. The key is passed via env (not a
// flag) so it stays out of process listings and shell history.
export function mcpServerConfig(opts: McpInstallOptions = {}): {
  command: string;
  args: string[];
  env: Record<string, string>;
} {
  const env: Record<string, string> = { SECLAYER_API_KEY: keyOrPlaceholder(opts) };
  const base = customBaseUrl(opts);
  if (base) env.SECLAYER_API_URL = base;
  return { command: 'npx', args: ['-y', MCP_PACKAGE], env };
}

// Generic config accepted by most clients (Claude Code `.mcp.json`, Cursor
// `.cursor/mcp.json`, Windsurf, Cline, Gemini CLI, …): the `mcpServers` wrapper.
export function mcpServersJson(opts: McpInstallOptions = {}): string {
  return JSON.stringify({ mcpServers: { [MCP_SERVER_NAME]: mcpServerConfig(opts) } }, null, 2);
}

// VS Code (and Copilot) use a `servers` key with an explicit `type`, not
// `mcpServers` — see `.vscode/mcp.json`.
export function vscodeMcpJson(opts: McpInstallOptions = {}): string {
  const { command, args, env } = mcpServerConfig(opts);
  return JSON.stringify({ servers: { [MCP_SERVER_NAME]: { type: 'stdio', command, args, env } } }, null, 2);
}

// The Claude Code one-liner. The key rides as --env so it's never a bare arg.
export function claudeCodeCommand(opts: McpInstallOptions = {}): string {
  const parts = [`claude mcp add ${MCP_SERVER_NAME}`, `--env SECLAYER_API_KEY=${keyOrPlaceholder(opts)}`];
  const base = customBaseUrl(opts);
  if (base) parts.push(`--env SECLAYER_API_URL=${base}`);
  parts.push(`-- npx -y ${MCP_PACKAGE}`);
  return parts.join(' ');
}

// The lowest-common-denominator launch: run the server directly with flags. Used
// as the manual fallback for any client not covered above.
export function npxCommand(opts: McpInstallOptions = {}): string {
  const parts = [`npx -y ${MCP_PACKAGE}`, `--key ${keyOrPlaceholder(opts)}`];
  const base = customBaseUrl(opts);
  if (base) parts.push(`--url ${base}`);
  return parts.join(' ');
}

// Base64 that works in both the browser (btoa) and the Node test runtime
// (Buffer). The payload is ASCII JSON, so btoa is safe; the Buffer branch keeps
// the module runnable under the plain node:test runner.
function toBase64(input: string): string {
  if (typeof btoa === 'function') return btoa(input);
  return Buffer.from(input, 'utf8').toString('base64');
}

// Cursor deeplink. `config` is base64 of the server entry (the value under the
// server name), then percent-encoded so base64's +/=/ survive the query string
// intact when Cursor decodes it.
export function cursorInstallUrl(opts: McpInstallOptions = {}): string {
  const config = toBase64(JSON.stringify(mcpServerConfig(opts)));
  const params = `name=${encodeURIComponent(MCP_SERVER_NAME)}&config=${encodeURIComponent(config)}`;
  return `cursor://anysphere.cursor-deeplink/mcp/install?${params}`;
}

// VS Code deeplink. The whole server object (named, with an explicit stdio type)
// is JSON then percent-encoded as the single query payload. `insiders` targets
// the Insiders build's URL scheme.
export function vscodeInstallUrl(opts: McpInstallOptions = {}, { insiders = false } = {}): string {
  const { command, args, env } = mcpServerConfig(opts);
  const payload = JSON.stringify({ name: MCP_SERVER_NAME, type: 'stdio', command, args, env });
  const scheme = insiders ? 'vscode-insiders' : 'vscode';
  return `${scheme}:mcp/install?${encodeURIComponent(payload)}`;
}
