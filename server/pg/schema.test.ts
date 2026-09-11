import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

// server/pg/schema.sql is applied on EVERY boot by PostgresDb.applySchema(), on
// every replica. That is only safe while two properties hold, and both are easy
// to break by adding one ordinary-looking statement — so they are pinned here
// rather than left to the file's header comment.
const sql = fs.readFileSync(path.join(process.cwd(), 'server', 'pg', 'schema.sql'), 'utf-8');

// Strip comments so a `-- DROP TABLE ...` note can't fail the scan.
const code = sql.replace(/--[^\n]*/g, '');

test('every CREATE/ALTER in schema.sql is idempotent', () => {
  const creates = code.match(/CREATE\s+(?:TABLE|INDEX|UNIQUE\s+INDEX)[\s\S]*?(?=\(|\bON\b)/gi) || [];
  assert.ok(creates.length > 0, 'expected to find CREATE statements to check');
  for (const c of creates) {
    assert.match(
      c,
      /IF\s+NOT\s+EXISTS/i,
      `non-idempotent statement would break the second boot: ${c.trim().slice(0, 80)}`,
    );
  }
  for (const a of code.match(/ALTER\s+TABLE[\s\S]*?;/gi) || []) {
    if (/ADD\s+COLUMN/i.test(a)) {
      assert.match(a, /IF\s+NOT\s+EXISTS/i, `ADD COLUMN must be idempotent: ${a.trim().slice(0, 80)}`);
    }
  }
});

test('schema.sql contains nothing that forbids running in a transaction', () => {
  // applySchema wraps the whole file in ONE transaction so a partial apply is
  // impossible. CREATE INDEX CONCURRENTLY / VACUUM cannot run inside one.
  for (const forbidden of [/CONCURRENTLY/i, /\bVACUUM\b/i, /CREATE\s+DATABASE/i, /ALTER\s+SYSTEM/i]) {
    assert.doesNotMatch(code, forbidden, `statement cannot run inside applySchema's transaction`);
  }
});

test('schema.sql is destructive-free — a boot must never drop data', () => {
  assert.doesNotMatch(code, /\bDROP\s+(TABLE|COLUMN|DATABASE|SCHEMA)\b/i);
  assert.doesNotMatch(code, /\bTRUNCATE\b/i);
});
