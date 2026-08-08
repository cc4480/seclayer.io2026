// T1-Auth-001 (Broken Authentication / weak session token) lives here: /login
// mints a predictable MD5(username + coarse timestamp) token and sets it in a
// cookie with httpOnly:false, secure:false — exactly the PRD's planted flaw.
// /login-hardened is the negative-control counterpart (T1-NC-003): a properly
// random, httpOnly, secure, sameSite=strict cookie, so a scanner that flags it
// too would be a false positive. Rate limiting on /login itself (T1-NC-002) is
// a SEPARATE, orthogonal control — a token can be both weak AND rate-limited.
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const db = require('./db');

// token -> userId. In-memory, fine for a throwaway single-process fixture.
const sessions = new Map();

function mintWeakToken(username) {
  // Deliberately coarse (per-second) timestamp, per the PRD — this is what
  // makes the token brute-forceable within a small window.
  return crypto.createHash('md5').update(username + Math.floor(Date.now() / 1000)).digest('hex');
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts, please try again later.' },
});

function login(req, res) {
  const { username, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE username = ? AND password = ?').get(username, password);
  if (!user) return res.status(401).json({ error: 'invalid credentials' });

  const token = mintWeakToken(username);
  sessions.set(token, user.id);
  res.cookie('sessionId', token, { httpOnly: false, secure: false });
  res.json({ success: true, token, userId: user.id });
}

function loginHardened(req, res) {
  const { username, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE username = ? AND password = ?').get(username, password);
  if (!user) return res.status(401).json({ error: 'invalid credentials' });

  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, user.id);
  res.cookie('sessionIdHardened', token, { httpOnly: true, secure: true, sameSite: 'strict' });
  res.json({ success: true, token, userId: user.id });
}

// Accepts either an Authorization: Bearer <token> header or a sessionId
// cookie — matches how Seclayer's authHeader scan option and a browser cookie
// jar would each reach this app.
function requireSession(req, res, next) {
  const bearer = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '').trim();
  const cookieToken = req.cookies && req.cookies.sessionId;
  const token = bearer || cookieToken;
  const userId = token && sessions.get(token);
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  req.userId = userId;
  next();
}

module.exports = { sessions, login, loginHardened, loginLimiter, requireSession };
