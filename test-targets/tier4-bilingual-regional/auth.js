// Simple session auth — real random tokens (this tier isn't about weak
// tokens), just enough plumbing for the i18n-bypass vulnerability to be
// meaningful (there has to be a REAL auth check somewhere for one locale to
// skip). Accepts either an Authorization: Bearer <token> header or a
// sessionId cookie, matching how Seclayer's authHeader scan option and a
// browser cookie jar would each reach this app.
const crypto = require('crypto');
const db = require('./db');

const sessions = new Map(); // token -> userId

function login(req, res) {
  const { email, password } = req.body || {};
  if (typeof email !== 'string' || typeof password !== 'string') return res.status(401).json({ error: 'invalid credentials' });
  const user = db.prepare('SELECT * FROM users WHERE email = ? AND password = ?').get(email, password);
  if (!user) return res.status(401).json({ error: 'invalid credentials' });

  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, user.id);
  res.cookie('sessionId', token, { httpOnly: true, secure: false, sameSite: 'lax' });
  res.json({ success: true, token, userId: user.id, role: user.role });
}

function requireSession(req, res, next) {
  const bearer = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '').trim();
  const cookieToken = req.cookies && req.cookies.sessionId;
  const token = bearer || cookieToken;
  const userId = token && sessions.get(token);
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  req.userId = userId;
  req.user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  next();
}

function requireAdmin(req, res, next) {
  requireSession(req, res, () => {
    if (!req.user || req.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
    next();
  });
}

module.exports = { sessions, login, requireSession, requireAdmin };
