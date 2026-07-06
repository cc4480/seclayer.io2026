import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mapOwasp } from './owasp.js';

test('maps injection findings to A03', () => {
  assert.match(mapOwasp('RED_TEAM', 'Active SQL Injection Probe'), /^A03:/);
  assert.match(mapOwasp('DAST', 'Reflected XSS (discovered parameter)'), /^A03:/);
  assert.match(mapOwasp('RED_TEAM', 'Active OS Command Injection'), /^A03:/);
});

test('maps SSRF to A10', () => {
  assert.match(mapOwasp('RED_TEAM', 'Active Server-Side Request Forgery (SSRF)'), /^A10:/);
});

test('maps access-control findings to A01', () => {
  assert.match(mapOwasp('API_SEC', 'Broken Object Level Authorization (BOLA)'), /^A01:/);
  assert.match(mapOwasp('DAST', 'phpMyAdmin Panel Exposed'), /^A01:/);
});

test('maps outdated components to A06', () => {
  assert.match(mapOwasp('SCA', 'Outdated Library Vulnerability Detected (jQuery)'), /^A06:/);
  assert.match(mapOwasp('SCA', 'package.json Exposed'), /^A06:/);
});

test('maps transport/secret exposure to A02', () => {
  assert.match(mapOwasp('EASM', 'Insecure Connection Protocol (HTTP)'), /^A02:/);
  assert.match(mapOwasp('IAST', 'Missing Strict-Transport-Security (HSTS) Policy'), /^A02:/);
  assert.match(mapOwasp('SAST', 'Exposed Credential Signature (Stripe Secret Key)'), /^A02:/);
});

test('maps SRI to A08', () => {
  assert.match(mapOwasp('SCA', 'Missing Subresource Integrity (SRI) on external vendor assets'), /^A08:/);
});

test('defaults to A05 security misconfiguration', () => {
  assert.match(mapOwasp('IAST', 'Missing Content-Security-Policy (CSP)'), /^A05:/);
  assert.match(mapOwasp('IAST', 'Missing X-Frame-Options / Clickjacking Immunity'), /^A05:/);
  assert.match(mapOwasp('DAST', 'Spring Boot Actuator /env Exposed'), /^A05:/);
  assert.match(mapOwasp('EASM', 'Verbose Server Framework Signature Leaked'), /^A05:/);
});
