// T1-DataExposure-001 — GET /api/settings returns hardcoded secrets in plain
// JSON with no authentication. All values below are fake/inert (this process
// never talks to Stripe, a real database, or a real SMTP server). The apiKey
// is deliberately NOT shaped like a real Stripe key (GitHub's push protection
// blocks that pattern regardless of realness) — doesn't affect this
// endpoint's result either way, since it's a confirmed gap for an unrelated
// reason: SAST secret-signature scanning never looks at non-root JSON
// responses at all (see vulnerabilities.json).
const express = require('express');

const router = express.Router();

router.get('/api/settings', (req, res) => {
  res.json({
    password: 'admin123SecurePassword',
    dbUrl: 'postgresql://user:pass@db.local:5432/app',
    apiKey: 'FAKE-NOT-A-REAL-KEY-1234567890abcdef',
    jwtSecret: 'supersecretkey12345',
    smtpPassword: 'mailPassword@123',
  });
});

module.exports = router;
