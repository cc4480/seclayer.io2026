// T4-Token-Reuse-001 — a reset token minted for one locale is redeemable via
// EITHER locale's reset endpoint: the token is stored globally with no
// locale binding, and /api/:locale/auth/reset-password never checks that the
// redeeming locale matches the one the token was issued under. The token is
// echoed in the response so this fixture is testable without a real email
// transport (same convention as Tier 1/2's fixtures).
//
// T4-NC-... (reuse-prevention half of the safe pair) — the *-safe endpoints
// bind the token to its issuing locale and reject a cross-locale redemption.
const crypto = require('crypto');
const express = require('express');
const db = require('../db');

const router = express.Router();

function issueToken(email, locale) {
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO password_resets (email, token, locale, expires) VALUES (?, ?, ?, ?)')
    .run(email, token, locale, Date.now() + 3600000);
  return token;
}

router.post('/api/:locale/auth/forgot-password', (req, res) => {
  const locale = req.params.locale === 'es' ? 'es' : 'en';
  const email = (req.body && req.body.email) || '';
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) return res.json({ success: true }); // don't reveal account existence
  const token = issueToken(email, locale);
  res.json({ success: true, resetToken: token }); // echoed for fixture testability
});

// VULNERABLE: accepts the token regardless of which locale issued it.
router.post('/api/:locale/auth/reset-password', (req, res) => {
  const { token, newPassword } = req.body || {};
  if (typeof token !== 'string' || typeof newPassword !== 'string') return res.status(400).json({ error: 'invalid request' });
  const reset = db.prepare('SELECT * FROM password_resets WHERE token = ? AND expires > ?').get(token, Date.now());
  if (!reset) return res.status(400).json({ error: 'invalid or expired token' });
  db.prepare('UPDATE users SET password = ? WHERE email = ?').run(newPassword, reset.email);
  db.prepare('DELETE FROM password_resets WHERE token = ?').run(token);
  res.json({ success: true });
});

router.post('/api/:locale/auth/forgot-password-safe', (req, res) => {
  const locale = req.params.locale === 'es' ? 'es' : 'en';
  const email = (req.body && req.body.email) || '';
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) return res.json({ success: true });
  const token = issueToken(email, locale);
  res.json({ success: true, resetToken: token });
});

// SAFE: requires the redeeming locale to match the issuing locale.
router.post('/api/:locale/auth/reset-password-safe', (req, res) => {
  const locale = req.params.locale === 'es' ? 'es' : 'en';
  const { token, newPassword } = req.body || {};
  if (typeof token !== 'string' || typeof newPassword !== 'string') return res.status(400).json({ error: 'invalid request' });
  const reset = db.prepare('SELECT * FROM password_resets WHERE token = ? AND locale = ? AND expires > ?').get(token, locale, Date.now());
  if (!reset) return res.status(400).json({ error: 'invalid or expired token' });
  db.prepare('UPDATE users SET password = ? WHERE email = ?').run(newPassword, reset.email);
  db.prepare('DELETE FROM password_resets WHERE token = ?').run(token);
  res.json({ success: true });
});

module.exports = router;
