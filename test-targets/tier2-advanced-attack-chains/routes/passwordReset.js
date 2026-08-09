// T2-WeakCrypto-001 — POST /api/forgot-password mints a reset token with
// Math.random().toString(36).substring(2): not cryptographically secure, and
// (unlike Tier 1's hash-of-predictable-seed token) genuinely LOW-ENTROPY
// OUTPUT — only ~11-13 base36 characters, versus a real crypto.randomBytes
// token's 32+ bytes. The token is echoed back in the response so this
// fixture is testable without a real email transport.
//
// T2-NC-001 (negative control) — the SAME endpoint is itself rate-limited
// (10/hour), so a scanner must not report it as brute-forceable.
const express = require('express');
const rateLimit = require('express-rate-limit');

const router = express.Router();
const RESET_TOKENS = new Map();

const forgotPasswordLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});

router.post('/api/forgot-password', forgotPasswordLimiter, (req, res) => {
  const email = (req.body && req.body.email) || '';
  const token = Math.random().toString(36).substring(2); // VULNERABLE: short, not a CSPRNG
  RESET_TOKENS.set(token, { email, expires: Date.now() + 3600000 });
  res.json({ success: true, message: 'Check your email for a reset link.', token });
});

router.post('/api/reset-password', (req, res) => {
  const { token, newPassword } = req.body || {};
  const entry = typeof token === 'string' ? RESET_TOKENS.get(token) : undefined;
  if (!entry || entry.expires < Date.now() || typeof newPassword !== 'string') {
    return res.status(400).json({ error: 'invalid or expired token' });
  }
  RESET_TOKENS.delete(token);
  res.json({ success: true });
});

module.exports = router;
