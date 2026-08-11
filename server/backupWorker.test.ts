import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Backups run against the shared db singleton; use an in-memory instance.
process.env.DB_PATH = ':memory:';
const { db } = await import('./db.js');
const { snapshotFilename, pruneOldBackups, backupConfig, runBackup } = await import('./backupWorker.js');

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'seclayer-backup-'));
}

test('snapshotFilename is filesystem-safe and lexically time-ordered', () => {
  const earlier = snapshotFilename(new Date('2026-01-01T00:00:00.000Z'));
  const later = snapshotFilename(new Date('2026-01-02T00:00:00.000Z'));
  assert.match(earlier, /^seclayer-[\dTZ-]+\.sqlite$/);
  assert.ok(!earlier.includes(':') && !earlier.includes('.sqlite.'), 'no path-hostile characters');
  assert.ok(earlier < later, 'lexical order must match chronological order');
});

test('backupConfig disables snapshots for an in-memory database', () => {
  const cfg = backupConfig();
  assert.equal(cfg.inMemory, true);
  assert.equal(cfg.disabled, true);
});

test('runBackup is a no-op (returns null) when disabled', async () => {
  assert.equal(await runBackup(), null);
});

test('db.backupTo writes a valid, self-contained SQLite snapshot', async () => {
  const dir = tmpDir();
  const dest = path.join(dir, 'snap.sqlite');
  (await db.backupTo(dest));
  assert.ok(fs.existsSync(dest), 'snapshot file must exist');
  // VACUUM INTO produces a single clean file — no companion WAL/SHM.
  assert.ok(!fs.existsSync(dest + '-wal'), 'snapshot must not carry a hot WAL');
  const header = fs.readFileSync(dest).subarray(0, 16).toString('latin1');
  assert.ok(header.startsWith('SQLite format 3'), 'file must be a real SQLite database');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('pruneOldBackups keeps only the newest N snapshots and ignores foreign files', () => {
  const dir = tmpDir();
  for (const stamp of ['2026-01-01', '2026-01-02', '2026-01-03', '2026-01-04']) {
    fs.writeFileSync(path.join(dir, `seclayer-${stamp}T00-00-00-000Z.sqlite`), 'x');
  }
  fs.writeFileSync(path.join(dir, 'keep-me.txt'), 'operator file'); // must survive

  const deleted = pruneOldBackups(dir, 2);
  assert.equal(deleted.length, 2, 'two oldest snapshots pruned');
  assert.ok(deleted[0].includes('2026-01-01') && deleted[1].includes('2026-01-02'), 'oldest first');

  const remaining = fs.readdirSync(dir).sort();
  assert.deepEqual(remaining, [
    'keep-me.txt',
    'seclayer-2026-01-03T00-00-00-000Z.sqlite',
    'seclayer-2026-01-04T00-00-00-000Z.sqlite',
  ], 'newest two snapshots and the foreign file remain');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('pruneOldBackups is a no-op when under the retention limit', () => {
  const dir = tmpDir();
  fs.writeFileSync(path.join(dir, 'seclayer-2026-01-01T00-00-00-000Z.sqlite'), 'x');
  assert.deepEqual(pruneOldBackups(dir, 7), []);
  fs.rmSync(dir, { recursive: true, force: true });
});
