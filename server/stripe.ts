import Stripe from 'stripe';

// Real Stripe Checkout integration. Credits are NEVER granted on session
// creation — only when a signature-verified `checkout.session.completed`
// webhook is received. When STRIPE_SECRET_KEY is unset the feature is disabled
// (callers receive a clear "not configured" response) rather than mocked.

export interface CreditPack {
  id: 'single' | 'pack5' | 'pack20';
  name: string;
  credits: number;
  amountCents: number;
}

export const CREDIT_PACKS: Record<CreditPack['id'], CreditPack> = {
  single: { id: 'single', name: 'Single Scan Credit', credits: 1, amountCents: 2900 },
  pack5: { id: 'pack5', name: '5 Scan Credits', credits: 5, amountCents: 9900 },
  pack20: { id: 'pack20', name: '20 Scan Credits', credits: 20, amountCents: 29900 },
};

let client: Stripe | null = null;

export function isStripeConfigured(): boolean {
  return !!process.env.STRIPE_SECRET_KEY;
}

function getStripe(): Stripe {
  if (!process.env.STRIPE_SECRET_KEY) {
    throw new Error('Stripe is not configured (STRIPE_SECRET_KEY is missing).');
  }
  if (!client) {
    client = new Stripe(process.env.STRIPE_SECRET_KEY);
  }
  return client;
}

// Creates a Checkout Session for a credit pack and returns the hosted URL.
// userId + credits are embedded in metadata so the webhook can grant credits.
export async function createCheckoutSession(
  userId: string,
  packId: string,
  baseUrl: string,
): Promise<string> {
  const pack = CREDIT_PACKS[packId as CreditPack['id']];
  if (!pack) throw new Error('Invalid credit pack selected.');

  const session = await getStripe().checkout.sessions.create({
    mode: 'payment',
    line_items: [
      {
        quantity: 1,
        price_data: {
          currency: 'usd',
          unit_amount: pack.amountCents,
          product_data: { name: `Seclayer — ${pack.name}` },
        },
      },
    ],
    metadata: { userId, credits: String(pack.credits), packId: pack.id },
    success_url: `${baseUrl}/dashboard?checkout_success=true`,
    cancel_url: `${baseUrl}/dashboard?checkout_canceled=true`,
  });

  if (!session.url) throw new Error('Stripe did not return a checkout URL.');
  return session.url;
}

export interface CheckoutCompletion {
  userId: string;
  credits: number;
  sessionId: string;
}

// Verifies a webhook payload and, for a completed & paid checkout, returns the
// credit grant to apply. Returns null for other event types. Throws on an
// invalid signature so the caller can respond 400.
export function parseWebhookEvent(rawBody: Buffer, signature: string | undefined): CheckoutCompletion | null {
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) throw new Error('Stripe webhook secret (STRIPE_WEBHOOK_SECRET) is not configured.');
  if (!signature) throw new Error('Missing Stripe-Signature header.');

  const event = getStripe().webhooks.constructEvent(rawBody, signature, secret);

  if (event.type !== 'checkout.session.completed') return null;

  const session = event.data.object as Stripe.Checkout.Session;
  if (session.payment_status !== 'paid') return null;

  const userId = session.metadata?.userId;
  const credits = Number(session.metadata?.credits);
  if (!userId || !Number.isFinite(credits) || credits <= 0) return null;

  return { userId, credits, sessionId: session.id };
}
