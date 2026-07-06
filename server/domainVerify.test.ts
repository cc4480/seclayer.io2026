import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractDomain, generateVerificationToken, txtRecordName, WELL_KNOWN_PATH } from './domainVerify.js';

test('extractDomain normalizes scheme-less input and lowercases the host', () => {
  assert.equal(extractDomain('example.com'), 'example.com');
  assert.equal(extractDomain('HTTPS://Example.COM/path'), 'example.com');
  assert.equal(extractDomain('http://sub.example.com:8080'), 'sub.example.com');
});

test('generateVerificationToken produces unique, prefixed tokens', () => {
  const a = generateVerificationToken();
  const b = generateVerificationToken();
  assert.match(a, /^sl-verify-[0-9a-f]{32}$/);
  assert.notEqual(a, b);
});

test('txtRecordName scopes the challenge to a fixed subdomain', () => {
  assert.equal(txtRecordName('example.com'), '_seclayer-challenge.example.com');
});

test('WELL_KNOWN_PATH is a stable well-known path', () => {
  assert.equal(WELL_KNOWN_PATH, '/.well-known/seclayer-verification.txt');
});
