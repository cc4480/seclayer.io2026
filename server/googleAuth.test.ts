import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, SignJWT, exportJWK } from 'jose';
import { verifyGoogleIdToken } from './googleAuth.js';

// These exercise the CLAIM checks, which are the part specific to this app —
// signature verification itself is jose's, and is covered by its own suite.
// Every case here is a token an attacker can actually present to the public
// /api/auth/google endpoint.

const CLIENT_ID = 'test-client-id.apps.googleusercontent.com';

async function signedToken(claims: Record<string, unknown>, audience = CLIENT_ID) {
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const jwk = await exportJWK(publicKey);
  const token = await new SignJWT({ ...claims })
    .setProtectedHeader({ alg: 'RS256', kid: 'test-kid' })
    .setIssuer('https://accounts.google.com')
    .setAudience(audience)
    .setExpirationTime('5m')
    .sign(privateKey);
  return { token, jwk };
}

test('a token is rejected when Google sign-in is not configured', async () => {
  const prev = process.env.GOOGLE_CLIENT_ID;
  delete process.env.GOOGLE_CLIENT_ID;
  try {
    const { token } = await signedToken({ email: 'a@test.io', email_verified: true });
    assert.equal(await verifyGoogleIdToken(token), null);
  } finally {
    if (prev === undefined) delete process.env.GOOGLE_CLIENT_ID;
    else process.env.GOOGLE_CLIENT_ID = prev;
  }
});

test('garbage and empty credentials are rejected without throwing', async () => {
  // The endpoint is public, so malformed input is an expected condition — it
  // must return null rather than surface a 500.
  for (const bad of ['', 'not-a-jwt', 'a.b.c', '....']) {
    assert.equal(await verifyGoogleIdToken(bad), null, `should reject: ${JSON.stringify(bad)}`);
  }
});

// A token signed by a key that is NOT in Google's JWKS must never verify —
// this is the "attacker signs their own token" case.
test('a self-signed token is rejected (signature is not Google\'s)', async () => {
  const { token } = await signedToken({ email: 'attacker@evil.test', email_verified: true });
  assert.equal(await verifyGoogleIdToken(token), null);
});
