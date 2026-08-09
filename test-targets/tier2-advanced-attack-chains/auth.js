// T2-PrivEsc-001 (JWT alg:none privilege escalation) lives in
// verifyVulnerable/requireAuth below. Note this is a HAND-ROLLED verifier,
// not jsonwebtoken's own jwt.verify(): modern jsonwebtoken (confirmed
// against v9.0.3) hard-requires a signature to be present once a secret is
// supplied, which closes the classic alg:none bypass at the library level
// even if 'none' is naively included in the algorithms allowlist. That's
// good news for real jsonwebtoken users, but it means faithfully
// reproducing this still-real, still-common vulnerability class (a project
// that rolls its own JWT handling, or uses an old/naive verifier) needs a
// deliberately vulnerable verifier written by hand — exactly what a real
// vulnerable app's homegrown auth code looks like.
//
// requireAuthHardened (T2-NC-002) uses the REAL jsonwebtoken verify(),
// which is safe by default for this class of bug.
const jwt = require('jsonwebtoken'); // used only for SIGNING real tokens below
const crypto = require('crypto');

const JWT_SECRET = 'tier2-fixture-shared-secret-not-real';

function issueToken(username, role, opts) {
  return jwt.sign({ sub: username, role }, JWT_SECRET, { algorithm: 'HS256', expiresIn: (opts && opts.expiresIn) || '1h' });
}

function b64urlDecode(s) {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

// VULNERABLE: honors the token's OWN "alg" header instead of a fixed,
// server-chosen algorithm — including "none", which skips the signature
// check entirely. Anyone can mint a token claiming any role.
function verifyVulnerable(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('malformed token');
  const header = JSON.parse(b64urlDecode(parts[0]));
  const payload = JSON.parse(b64urlDecode(parts[1]));
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) throw new Error('expired');

  if (header.alg === 'none') return payload; // VULNERABLE: no signature check at all
  if (header.alg === 'HS256') {
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${parts[0]}.${parts[1]}`).digest('base64url');
    if (expected !== parts[2]) throw new Error('invalid signature');
    return payload;
  }
  throw new Error('unsupported algorithm');
}

function requireAuth(req, res, next) {
  const authz = req.headers['authorization'] || '';
  const token = authz.replace(/^Bearer\s+/i, '').trim();
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  try {
    req.user = verifyVulnerable(token);
    next();
  } catch (e) {
    res.status(401).json({ error: 'unauthorized' });
  }
}

// SAFE: the real jsonwebtoken verify(), locked to exactly ['HS256'].
function requireAuthHardened(req, res, next) {
  const authz = req.headers['authorization'] || '';
  const token = authz.replace(/^Bearer\s+/i, '').trim();
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  try {
    req.user = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    next();
  } catch (e) {
    res.status(401).json({ error: 'unauthorized' });
  }
}

module.exports = { issueToken, requireAuth, requireAuthHardened, JWT_SECRET };
