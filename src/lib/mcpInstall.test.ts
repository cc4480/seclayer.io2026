import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  mcpServerConfig,
  mcpServersJson,
  vscodeMcpJson,
  claudeCodeCommand,
  npxCommand,
  cursorInstallUrl,
  vscodeInstallUrl,
  PLACEHOLDER_KEY,
} from './mcpInstall.js';

const KEY = 'sl_live_abc123';

test('mcpServerConfig embeds the key via env and never as a flag', () => {
  const cfg = mcpServerConfig({ apiKey: KEY });
  assert.equal(cfg.command, 'npx');
  assert.deepEqual(cfg.args, ['-y', '@seclayer/mcp']);
  assert.equal(cfg.env.SECLAYER_API_KEY, KEY);
  // The key must not leak into argv — that's the whole point of using env.
  assert.ok(!cfg.args.some((a) => a.includes(KEY)));
});

test('a missing key falls back to a copy-paste placeholder, not empty', () => {
  assert.equal(mcpServerConfig().env.SECLAYER_API_KEY, PLACEHOLDER_KEY);
  assert.equal(mcpServerConfig({ apiKey: '' }).env.SECLAYER_API_KEY, PLACEHOLDER_KEY);
  assert.equal(mcpServerConfig({ apiKey: '   ' }).env.SECLAYER_API_KEY, PLACEHOLDER_KEY);
});

test('the default backend URL is omitted; only a custom one is threaded through', () => {
  assert.equal(mcpServerConfig({ apiKey: KEY }).env.SECLAYER_API_URL, undefined);
  assert.equal(mcpServerConfig({ apiKey: KEY, baseUrl: 'https://seclayer.app' }).env.SECLAYER_API_URL, undefined);
  // Trailing slash is normalized away before the comparison.
  assert.equal(mcpServerConfig({ apiKey: KEY, baseUrl: 'https://seclayer.app/' }).env.SECLAYER_API_URL, undefined);
  assert.equal(
    mcpServerConfig({ apiKey: KEY, baseUrl: 'http://localhost:3000' }).env.SECLAYER_API_URL,
    'http://localhost:3000',
  );
});

test('mcpServersJson is valid JSON with the standard mcpServers wrapper', () => {
  const parsed = JSON.parse(mcpServersJson({ apiKey: KEY }));
  assert.deepEqual(parsed.mcpServers.seclayer.args, ['-y', '@seclayer/mcp']);
  assert.equal(parsed.mcpServers.seclayer.env.SECLAYER_API_KEY, KEY);
});

test('vscodeMcpJson uses the servers key with an explicit stdio type', () => {
  const parsed = JSON.parse(vscodeMcpJson({ apiKey: KEY }));
  assert.equal(parsed.servers.seclayer.type, 'stdio');
  assert.equal(parsed.servers.seclayer.env.SECLAYER_API_KEY, KEY);
  assert.equal(parsed.mcpServers, undefined);
});

test('claudeCodeCommand passes the key as --env and the package after --', () => {
  const cmd = claudeCodeCommand({ apiKey: KEY });
  assert.equal(cmd, 'claude mcp add seclayer --env SECLAYER_API_KEY=sl_live_abc123 -- npx -y @seclayer/mcp');
});

test('a custom base URL is threaded into both CLI commands', () => {
  assert.match(claudeCodeCommand({ apiKey: KEY, baseUrl: 'http://localhost:3000' }), /--env SECLAYER_API_URL=http:\/\/localhost:3000/);
  assert.match(npxCommand({ apiKey: KEY, baseUrl: 'http://localhost:3000' }), /--url http:\/\/localhost:3000/);
});

test('cursorInstallUrl encodes a base64 config that round-trips to the server entry', () => {
  const url = cursorInstallUrl({ apiKey: KEY });
  assert.ok(url.startsWith('cursor://anysphere.cursor-deeplink/mcp/install?'));
  const config = new URL(url).searchParams.get('config');
  assert.ok(config, 'config param present');
  // Decode base64 (searchParams already percent-decoded it) back to the config.
  const decoded = JSON.parse(Buffer.from(config as string, 'base64').toString('utf8'));
  assert.equal(decoded.env.SECLAYER_API_KEY, KEY);
  assert.deepEqual(decoded.args, ['-y', '@seclayer/mcp']);
});

test('vscodeInstallUrl carries a named stdio payload and supports Insiders', () => {
  const url = vscodeInstallUrl({ apiKey: KEY });
  assert.ok(url.startsWith('vscode:mcp/install?'));
  const payload = JSON.parse(decodeURIComponent(url.split('?')[1]));
  assert.equal(payload.name, 'seclayer');
  assert.equal(payload.type, 'stdio');
  assert.equal(payload.env.SECLAYER_API_KEY, KEY);

  assert.ok(vscodeInstallUrl({ apiKey: KEY }, { insiders: true }).startsWith('vscode-insiders:mcp/install?'));
});
