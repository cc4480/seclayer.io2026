// T4-Stripe-Webhook-001 — signature verification is SKIPPED for any
// non-USD event. A minimal, self-contained HMAC-SHA256 "signature" scheme
// stands in for the real Stripe SDK's webhooks.constructEvent (same
// verification shape: HMAC over the raw body with a shared secret) so this
// fixture doesn't need a real Stripe account — the planted bug (conditional
// verification by currency) is what's being tested, not Stripe's own
// signature format.
const crypto = require('crypto');
const express = require('express');

const router = express.Router();
const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || 'whsec_fixture_not_a_real_secret';

const PROCESSED = []; // observable side effect: accepted webhooks land here

function computeSignature(rawBody) {
  return crypto.createHmac('sha256', WEBHOOK_SECRET).update(rawBody).digest('hex');
}

function verifySignature(rawBody, signatureHeader) {
  if (!signatureHeader) return false;
  const expected = computeSignature(rawBody);
  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(String(signatureHeader), 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

router.post('/api/webhooks/stripe', (req, res) => {
  let event;
  try {
    event = JSON.parse(req.rawBody.toString('utf8'));
  } catch {
    return res.status(400).json({ error: 'invalid payload' });
  }
  const currency = event && event.data && event.data.object && event.data.object.currency;

  // VULNERABLE: only verify the signature for USD events.
  if (currency === 'usd') {
    if (!verifySignature(req.rawBody, req.headers['stripe-signature'])) {
      return res.status(400).json({ error: 'invalid signature' });
    }
  }

  PROCESSED.push(event);
  res.json({ received: true });
});

router.post('/api/webhooks/stripe-safe', (req, res) => {
  if (!verifySignature(req.rawBody, req.headers['stripe-signature'])) {
    return res.status(400).json({ error: 'invalid signature' });
  }
  let event;
  try {
    event = JSON.parse(req.rawBody.toString('utf8'));
  } catch {
    return res.status(400).json({ error: 'invalid payload' });
  }
  PROCESSED.push(event);
  res.json({ received: true });
});

// Test-only introspection so manual verification can confirm an event was
// actually accepted/processed, not just that the HTTP call returned 200.
router.get('/api/webhooks/_debug/processed', (_req, res) => {
  res.json(PROCESSED);
});

module.exports = router;
