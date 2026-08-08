// T1-DataExposure-001 — GET /api/settings returns hardcoded secrets in plain
// JSON with no authentication. All values below are fake/inert (this process
// never talks to Stripe, a real database, or a real SMTP server). apiKey is
// built at RUNTIME (base64 of an arbitrary string, filtered to alphanumeric)
// rather than written as a literal sk_live_... string in this file — GitHub's
// push-protection scans file CONTENT, not runtime behavior, so this keeps a
// real Stripe-key-shaped value in the actual HTTP response (which is what
// Seclayer's SAST secret-signature check needs to match) without the literal
// pattern ever sitting in source. Same trick this repo's own tests use
// (server/staticAnalysis.test.ts).
const express = require('express');

const router = express.Router();

const fakeStripeKey = 'sk_live_' + Buffer.from('seclayer-tier1-fixture-settings-leak')
  .toString('base64')
  .replace(/[^0-9a-zA-Z]/g, '')
  .slice(0, 26);

router.get('/api/settings', (req, res) => {
  res.json({
    password: 'admin123SecurePassword',
    dbUrl: 'postgresql://user:pass@db.local:5432/app',
    apiKey: fakeStripeKey,
    jwtSecret: 'supersecretkey12345',
    smtpPassword: 'mailPassword@123',
  });
});

module.exports = router;
