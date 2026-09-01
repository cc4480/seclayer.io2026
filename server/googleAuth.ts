// Verification for "Sign in with Google" ID tokens (Google Identity Services).
//
// GIS hands the BROWSER a signed JWT; the browser posts it here. That token is
// the entire proof of identity, so nothing about it may be trusted until the
// signature and claims are checked server-side — a token is attacker-supplied
// input like any other request body.
//
// Verification is delegated to `jose` rather than hand-rolled: this is
// authentication, and the failure modes of a bespoke RS256/JWKS implementation
// (accepting `alg: none`, skipping `aud`, ignoring key rotation) are silent and
// total. createRemoteJWKSet also caches Google's signing keys and re-fetches
// them when they rotate, which they do regularly.
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { config } from './config.js';

// Google's published signing keys. Built lazily and reused so the key set is
// cached across sign-ins instead of refetched per request.
const GOOGLE_JWKS_URL = new URL('https://www.googleapis.com/oauth2/v3/certs');
let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;
function keySet() {
  if (!jwks) jwks = createRemoteJWKSet(GOOGLE_JWKS_URL);
  return jwks;
}

// Google mints tokens under both spellings; either is legitimate.
const GOOGLE_ISSUERS = ['accounts.google.com', 'https://accounts.google.com'];

export interface GoogleIdentity {
  email: string;
  name?: string;
}

// Returns the verified identity, or null when the token is unusable for sign-in.
// Never throws on a bad token: a malformed, expired, wrongly-audienced or
// unverified-email token is an expected condition on a public endpoint, not an
// exceptional one, so callers get a simple null and answer 401.
export async function verifyGoogleIdToken(idToken: string): Promise<GoogleIdentity | null> {
  if (!config.googleClientId || !idToken) return null;

  let payload: Record<string, unknown>;
  try {
    // Checks the signature against Google's current keys, plus `iss`, `aud` and
    // expiry. `aud` is the load-bearing one: without it, a token minted for a
    // DIFFERENT Google app would verify perfectly and log its bearer in here.
    ({ payload } = await jwtVerify(idToken, keySet(), {
      issuer: GOOGLE_ISSUERS,
      audience: config.googleClientId,
    }));
  } catch {
    return null;
  }

  const email = typeof payload.email === 'string' ? payload.email.toLowerCase().trim() : '';
  // Google sets email_verified=false for some workspace/unverified accounts.
  // Accepting those would let someone sign in as an address they don't control,
  // which — because this app keys identity on email — would hand them an
  // existing magic-link account.
  if (!email || payload.email_verified !== true) return null;

  return { email, name: typeof payload.name === 'string' ? payload.name : undefined };
}
