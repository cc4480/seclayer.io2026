import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeLibraries, extractResourceRefs, analyzeSecrets, analyzeDataDumpExposure, maskSecret } from './staticAnalysis.js';

const scriptTag = (url: string) => `<html><head><script src="${url}"></script></head><body></body></html>`;

test('flags a vulnerable jQuery loaded via <script src>', () => {
  const libs = analyzeLibraries(scriptTag('/vendor/jquery-1.12.4.min.js'));
  assert.equal(libs.length, 1);
  assert.equal(libs[0].name, 'jQuery');
  assert.equal(libs[0].version, '1.12.4');
});

test('does NOT flag a version string that only appears in prose/comments (SCA false positive)', () => {
  // A changelog/comment mentioning an old version must not be read as a loaded dep.
  const html = `<html><body><p>We migrated off jquery-1.9.0 last year.</p><!-- was lodash-4.17.4 --></body></html>`;
  assert.deepEqual(analyzeLibraries(html), []);
});

test('extractResourceRefs pulls only src/href URLs', () => {
  const refs = extractResourceRefs(`<script src="/a/jquery-1.12.4.js"></script><link href="/b.css"><p>jquery-2.0.0</p>`);
  assert.match(refs, /jquery-1\.12\.4/);
  assert.match(refs, /b\.css/);
  assert.ok(!refs.includes('2.0.0'), 'prose text is not a resource ref');
});

test('Lodash: vulnerable 4.17.x line (< 4.17.21) is now flagged', () => {
  for (const v of ['4.17.4', '4.17.11', '4.17.20', '4.16.6', '4.0.0']) {
    const libs = analyzeLibraries(scriptTag(`https://cdn.example/lodash@${v}/lodash.min.js`));
    assert.equal(libs.length, 1, `lodash ${v} should be flagged`);
    assert.equal(libs[0].version, v);
  }
});

test('Lodash: patched 4.17.21+ is NOT flagged', () => {
  for (const v of ['4.17.21', '4.17.22', '4.18.0']) {
    assert.deepEqual(analyzeLibraries(scriptTag(`https://cdn.example/lodash@${v}/lodash.min.js`)), [],
      `lodash ${v} must not be flagged`);
  }
});

test('secret detection screens low-entropy placeholders but flags a high-entropy key', () => {
  // Low-entropy filler (all one character) is screened out as a placeholder.
  assert.equal(analyzeSecrets('const k = "sk_live_' + 'a'.repeat(30) + '";').length, 0, 'filler is a placeholder');
  // A high-entropy key is detected. Built at runtime from base64 so no literal
  // secret is ever committed to the repo (which would trip secret push protection).
  const body = Buffer.from('seclayer-synthetic-entropy-seed-01').toString('base64').replace(/[^0-9a-zA-Z]/g, '').slice(0, 26);
  const detected = analyzeSecrets('const k = "sk_live_' + body + '";');
  assert.equal(detected.length, 1, 'a high-entropy sk_live-shaped key is a real detection');
  assert.match(detected[0].issue, /Stripe/);
});

test('flags a world-readable PostgreSQL pg_dump (header comment)', () => {
  const dump = `--\n-- PostgreSQL database dump\n--\n\nSET statement_timeout = 0;\n`;
  const findings = analyzeDataDumpExposure(dump, 'http://target/backups/db.sql');
  assert.equal(findings.length, 1);
  assert.match(findings[0].issue, /PostgreSQL Database Dump/);
  assert.equal(findings[0].severity, 'critical');
  assert.equal(findings[0].file, 'http://target/backups/db.sql');
});

test('flags a world-readable PostgreSQL dump via a bare COPY ... FROM stdin block (no header)', () => {
  const dump = `COPY public.profiles (id, user_id, email) FROM stdin;\n1\tuuid\talice@corp.test\n\\.\n`;
  const findings = analyzeDataDumpExposure(dump, 'http://target/backups/db.sql');
  assert.equal(findings.length, 1);
  assert.match(findings[0].issue, /PostgreSQL Database Dump/);
});

test('flags a world-readable mysqldump', () => {
  const dump = `-- MySQL dump 10.13  Distrib 8.0.34\nCREATE TABLE users (id int);\n`;
  const findings = analyzeDataDumpExposure(dump, 'http://target/backup.sql');
  assert.equal(findings.length, 1);
  assert.match(findings[0].issue, /MySQL Database Dump/);
});

test('does NOT flag ordinary prose that merely mentions SQL/dumps/tables', () => {
  const prose = '<html><body><p>Learn how to CREATE TABLE and dump your data with pg_dump.</p></body></html>';
  assert.deepEqual(analyzeDataDumpExposure(prose, 'http://target/blog/post'), []);
});

test('does NOT flag an empty or unrelated body', () => {
  assert.deepEqual(analyzeDataDumpExposure('', 'http://target/'), []);
  assert.deepEqual(analyzeDataDumpExposure('<html><body>hello</body></html>', 'http://target/'), []);
});

test('Private Key Block: a PEM formatting template is not a leaked key (JSEncrypt FP)', () => {
  // JSEncrypt and similar RSA libraries, loaded on countless login forms, hold
  // the header literal to format their output — no key material near it. The
  // bare-header pattern reported that as a CVSS-critical on every such site.
  const jsencrypt = 'getPrivateKey:function(){var t="-----BEGIN RSA PRIVATE KEY-----\n";return t+e(this.getPrivateBaseKeyB64())}';
  const hit = analyzeSecrets(jsencrypt).filter((f) => /Private Key/i.test(f.issue ?? ""));
  assert.equal(hit.length, 0, 'a formatting template must not be a finding');
});

test('Private Key Block: a real key embedded in source is still caught', () => {
  const inline = '"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7Yn3kQ2mVrJk1pQ0zXcFbN9dLmVpQrStUvWxYzAbCdEf\n"';
  const hit = analyzeSecrets(inline).filter((f) => /Private Key/i.test(f.issue ?? ""));
  assert.equal(hit.length, 1, 'a genuine embedded key must still be reported');
});

// A report is stored, shared and exported, so a leaked credential must never be
// one of the things it stores. But "a string matching the AWS format was found"
// is unactionable when you hold forty keys — so the receipt carries a masked
// excerpt: leading token + last four, middle starred, true length stated.
test('maskSecret reveals which credential leaked, never a usable one', () => {
  const key = 'AKIAIOSFODNN7REALKEY';           // 20 chars
  const masked = maskSecret(key);
  assert.match(masked, /^AKIA\*+LKEY \(20 chars\)$/);
  assert.ok(!masked.includes(key), 'the raw value must never appear');
  // Enough hidden that the excerpt cannot be used: only 8 of 20 chars shown.
  assert.equal((masked.match(/\*/g) || []).length, 12);
});

test('maskSecret hides a short secret almost entirely', () => {
  // Four-and-four would be most of a short value, so reveal only the length.
  assert.equal(maskSecret('abc123'), '****** (6 chars)');
  assert.equal(maskSecret('twelvechars1'), '************ (12 chars)');
});

test('maskSecret caps the mask so a huge token cannot bloat the report', () => {
  const long = 'sk_live_' + 'x'.repeat(300);
  const masked = maskSecret(long);
  assert.ok(masked.length < 60, 'masked excerpt stays short');
  assert.match(masked, /^sk_l\*+/);
  assert.match(masked, /\(308 chars\)$/);
});

test('analyzeSecrets carries a masked excerpt, not the raw credential', () => {
  const raw = 'AKIAIOSFODNN7REALKEY';
  const found = analyzeSecrets(`<script>const k="${raw}";</script>`, 'https://example.com/app.js');
  const aws = found.find((f) => /AWS/i.test(f.issue));
  assert.ok(aws, 'expected the AWS key signature to match');
  assert.ok(aws.masked, 'the finding carries a masked excerpt');
  assert.ok(!aws.masked!.includes(raw), 'the raw key is never stored on the finding');
  assert.ok(!JSON.stringify(aws).includes(raw), 'the raw key appears nowhere on the finding');
});
