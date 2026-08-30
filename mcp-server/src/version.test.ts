import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { VERSION } from './version.js';

const pkgDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (f: string) => JSON.parse(readFileSync(join(pkgDir, f), 'utf8'));

// The version is stated in three places that ship together — the constant the
// CLI prints, package.json (what npm publishes), and server.json (the MCP
// Registry manifest, which is INSIDE the published tarball). They drifted once:
// package.json was bumped to 1.0.0 for release while server.json still claimed
// 0.1.0, which would have published a manifest that disagreed with its own
// package and broken registry submission.
test('VERSION, package.json and server.json all state the same version', () => {
  const pkg = read('package.json');
  const server = read('server.json');

  assert.equal(pkg.version, VERSION, 'package.json version must match src/version.ts');
  assert.equal(server.version, VERSION, 'server.json version must match src/version.ts');
  assert.equal(
    server.packages[0].version,
    VERSION,
    'server.json packages[0].version must match src/version.ts',
  );
});

// The manifest advertises the npm package by name; a mismatch would point the
// registry at a package that doesn't exist.
test('server.json advertises the package name that package.json publishes', () => {
  const pkg = read('package.json');
  const server = read('server.json');

  assert.equal(server.packages[0].identifier, pkg.name);
  assert.equal(pkg.mcpName, server.name, 'package.json mcpName must match the manifest name');
});
