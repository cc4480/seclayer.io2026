import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CREDIT_PACKS, isStripeConfigured, createCheckoutSession, parseWebhookEvent } from './stripe.js';

test('credit packs are well-formed and priced', () => {
  for (const id of ['single', 'pack5', 'pack20'] as const) {
    const p = CREDIT_PACKS[id];
    assert.equal(p.id, id);
    assert.ok(p.credits > 0);
    assert.ok(p.amountCents > 0);
  }
  assert.equal(CREDIT_PACKS.pack5.credits, 5);
});

test('Stripe is reported unconfigured without a secret key', () => {
  const prev = process.env.STRIPE_SECRET_KEY;
  delete process.env.STRIPE_SECRET_KEY;
  assert.equal(isStripeConfigured(), false);
  if (prev) process.env.STRIPE_SECRET_KEY = prev;
});

test('checkout creation fails fast when Stripe is not configured', async () => {
  const prev = process.env.STRIPE_SECRET_KEY;
  delete process.env.STRIPE_SECRET_KEY;
  await assert.rejects(createCheckoutSession('user_1', 'pack5', 'https://app.test'), /not configured/i);
  if (prev) process.env.STRIPE_SECRET_KEY = prev;
});

test('an invalid pack is rejected', async () => {
  process.env.STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || 'sk_test_dummy';
  await assert.rejects(createCheckoutSession('user_1', 'not-a-pack', 'https://app.test'), /invalid credit pack/i);
});

test('webhook parsing requires a configured signing secret', () => {
  const prev = process.env.STRIPE_WEBHOOK_SECRET;
  delete process.env.STRIPE_WEBHOOK_SECRET;
  assert.throws(() => parseWebhookEvent(Buffer.from('{}'), 'sig'), /webhook secret/i);
  if (prev) process.env.STRIPE_WEBHOOK_SECRET = prev;
});
