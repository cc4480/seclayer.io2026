// T4-SMS-2FA-001 — /api/auth/verify-sms accepts unlimited code guesses: no
// rate limiting, no backoff, no lockout. A real 6-digit code space (1e6
// possibilities) can't be practically brute-forced in a benchmark run, but
// the vulnerability itself — the ABSENCE of any throttling — is provable
// with a small, bounded number of rapid wrong-code attempts: if none of N
// rapid attempts is ever rate-limited, that's the defect, independent of
// whether the correct code is ever actually found.
//
// T4-NC-002 (safe pair) — /api/auth/verify-sms-safe is rate-limited to 3
// attempts per 15 minutes via express-rate-limit, same shape as Tier 1's
// login limiter.
const crypto = require('crypto');
const express = require('express');
const rateLimit = require('express-rate-limit');
const db = require('../db');

const router = express.Router();

function issueCode(phone) {
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  db.prepare('INSERT INTO sms_verifications (phone, code, expires) VALUES (?, ?, ?)')
    .run(phone, code, Date.now() + 5 * 60 * 1000);
  return code;
}

router.post('/api/auth/request-sms', (req, res) => {
  const phone = (req.body && req.body.phoneNumber) || '';
  issueCode(phone); // real apps send this via SMS/WhatsApp; not echoed here — the endpoint itself sends nothing observable
  res.json({ success: true, message: 'Verification code sent.' });
});

// VULNERABLE: no rate limiting at all.
router.post('/api/auth/verify-sms', (req, res) => {
  const phone = (req.body && req.body.phoneNumber) || '';
  const code = (req.body && req.body.code) || '';
  const verif = db.prepare('SELECT * FROM sms_verifications WHERE phone = ? AND code = ? AND expires > ?').get(phone, code, Date.now());
  if (!verif) return res.status(400).json({ error: 'Invalid code' });
  const user = db.prepare('SELECT * FROM users WHERE phone = ?').get(phone);
  res.json({ success: true, token: crypto.randomBytes(16).toString('hex'), userId: user ? user.id : null });
});

const smsLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Try again in 15 minutes.' },
});

router.post('/api/auth/request-sms-safe', (req, res) => {
  const phone = (req.body && req.body.phoneNumber) || '';
  issueCode(phone);
  res.json({ success: true, message: 'Verification code sent.' });
});

router.post('/api/auth/verify-sms-safe', smsLimiter, (req, res) => {
  const phone = (req.body && req.body.phoneNumber) || '';
  const code = (req.body && req.body.code) || '';
  const verif = db.prepare('SELECT * FROM sms_verifications WHERE phone = ? AND code = ? AND expires > ?').get(phone, code, Date.now());
  if (!verif) return res.status(400).json({ error: 'Invalid code' });
  const user = db.prepare('SELECT * FROM users WHERE phone = ?').get(phone);
  res.json({ success: true, token: crypto.randomBytes(16).toString('hex'), userId: user ? user.id : null });
});

module.exports = router;
