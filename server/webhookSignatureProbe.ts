// Webhook signature-verification bypass probe (AGGRESSIVE tier). A payment/event
// webhook that verifies its signature only CONDITIONALLY (e.g. skips the check
// for non-USD currencies, or for certain event types) lets an attacker forge
// events and, in the real world, fake "payment succeeded" notifications.
//
// Proven with a differential that is deliberately made non-destructive:
//   * The probe sends an INVALIDLY-signed event that is a FAILURE type
//     (charge.failed) for a NONEXISTENT entity with amount 0. Accepting such an
//     event transfers no money and fulfills no order — the worst a handler can
//     do with it is a no-op / 404 — so proving the bypass never causes a real
//     financial side effect, unlike forging a *succeeded* event.
//   * If that invalidly-signed event is REJECTED under one currency (the
//     signature IS checked) yet ACCEPTED under another (the check is skipped),
//     signature verification is conditional -> proven. A webhook that verifies
//     unconditionally rejects both -> no finding (no false positive).
// Gated to the aggressive + ownership-verified tier; targets a curated webhook
// path list plus discovered POST endpoints.
import { safeFetch } from "./ssrf.js";
import type { RedTeamFinding } from "./scanTypes.js";
import type { ExploitEvidence } from "../src/types.js";
import { renderRawRequest } from "./evidence.js";

const WEBHOOK_PATHS = [
  "/api/webhooks/stripe", "/webhooks/stripe", "/api/stripe/webhook", "/stripe/webhook",
  "/api/webhooks", "/webhook", "/api/webhook", "/hooks/stripe", "/api/payment/webhook",
];

// An obviously-invalid signature: well-formed enough to reach the verify step,
// but no correct verifier accepts it.
const BAD_SIG = "0000000000000000000000000000000000000000000000000000000000000000";
// A non-crediting FAILURE event for a nonexistent, zero-amount entity — so even
// if it is accepted, nothing of value is processed.
const FAKE_ID = "seclayer_probe_nonexistent_0000";
const eventBody = (currency: string) =>
  JSON.stringify({ id: `evt_${FAKE_ID}`, type: "charge.failed", data: { object: { id: `ch_${FAKE_ID}`, currency, amount: 0, status: "failed" } } });

// The currency the vulnerable fixture (and the common real bug) still verifies,
// vs. the ones it skips. First entry is the "verified" control.
const VERIFIED_CURRENCY = "usd";
const SKIPPED_CURRENCIES = ["mxn", "eur", "gbp", "cad", "brl"];

const REJECTED = new Set([400, 401, 403]);
const ACCEPTED = (s: number) => s >= 200 && s < 300;

async function postSigned(url: string, headers: Record<string, string>, currency: string): Promise<{ res: Response; text: string }> {
  const ctl = new AbortController();
  const id = setTimeout(() => ctl.abort(), 5000);
  try {
    const res = await safeFetch(url, {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/json", "Stripe-Signature": BAD_SIG },
      body: eventBody(currency),
      signal: ctl.signal,
    });
    return { res, text: await res.text().catch(() => "") };
  } finally {
    clearTimeout(id);
  }
}

export async function probeWebhookSignatureBypass(
  rootUrl: string,
  postUrls: string[],
  headers: Record<string, string>,
): Promise<RedTeamFinding | null> {
  const base = rootUrl.replace(/\/+$/, "");
  const candidates = [...new Set([...WEBHOOK_PATHS.map((p) => `${base}${p}`), ...postUrls])];
  const sigHeaders = { ...headers, "Content-Type": "application/json", "Stripe-Signature": BAD_SIG };

  for (const url of candidates) {
    // Control: the verified currency with a bad signature MUST be rejected —
    // otherwise this endpoint isn't signature-gating anything we can prove a
    // *conditional* bypass against (an endpoint that accepts everything is a
    // different, ambiguous case we don't flag here to stay low-FP).
    let control: { res: Response; text: string };
    try { control = await postSigned(url, headers, VERIFIED_CURRENCY); } catch { continue; }
    if (!REJECTED.has(control.res.status)) continue;

    for (const currency of SKIPPED_CURRENCIES) {
      let attack: { res: Response; text: string };
      try { attack = await postSigned(url, headers, currency); } catch { continue; }
      if (!ACCEPTED(attack.res.status)) continue; // still rejected for this currency — good, keep looking

      // Proven: identical bad signature, only the currency differs, yet one is
      // rejected and the other accepted -> signature verification is conditional.
      const quote = (attack.text.trim().slice(0, 60)) || `${attack.res.status} ${attack.res.statusText}`;
      const attackResponse = `HTTP/1.1 ${attack.res.status} ${attack.res.statusText}\n\n` + (attack.text.length > 800 ? attack.text.slice(0, 800) + "\n[…truncated]" : attack.text);
      const evidence: ExploitEvidence = {
        method: "differential",
        attack: { request: renderRawRequest("POST", url, sigHeaders, eventBody(currency)), response: attackResponse },
        control: {
          request: renderRawRequest("POST", url, sigHeaders, eventBody(VERIFIED_CURRENCY)),
          response: `HTTP/1.1 ${control.res.status} ${control.res.statusText}\n\n` + (control.text.length > 400 ? control.text.slice(0, 400) : control.text),
        },
        signal: {
          quote,
          offsetInResponse: attackResponse.indexOf(quote),
          why: `The exact same invalidly-signed webhook was REJECTED (${control.res.status}) with currency "${VERIFIED_CURRENCY}" but ACCEPTED (${attack.res.status}) with currency "${currency}" — signature verification runs only for some currencies, so an attacker can forge events in "${currency}".`,
        },
        demonstration: `We POSTed a webhook event with a deliberately-invalid signature. With currency "${VERIFIED_CURRENCY}" the server rejected it (${control.res.status}); with currency "${currency}" — same bad signature — it accepted it (${attack.res.status}). Signature verification is conditional on the currency, so an attacker can submit forged webhook events (e.g. a fake "payment succeeded") simply by choosing a currency the check skips. We proved this with a zero-amount charge.failed event for a nonexistent charge, so no real payment was processed.`,
        reproduction: `curl -s -i -X POST "${url}" -H "Content-Type: application/json" -H "Stripe-Signature: ${BAD_SIG}" --data '${eventBody(currency)}'`,
        capturedAt: new Date().toISOString(),
      };
      return {
        testName: "Webhook Signature Verification Bypass (conditional on payload)",
        payload: eventBody(currency),
        severity: "high",
        description:
          `A payment/event webhook verifies its signature only conditionally: an invalidly-signed event was rejected for currency "${VERIFIED_CURRENCY}" but accepted for currency "${currency}". An attacker can forge webhook events (e.g. a fake "payment succeeded", subscription grant, or balance credit) by choosing a currency/shape the signature check skips, with no valid signing secret. Proven non-destructively with a zero-amount failure event for a nonexistent entity.`,
        fix: "Verify the webhook signature UNCONDITIONALLY, before any branching on the payload (currency, event type, amount). Use the provider SDK's constructEvent/verifyHeader on the raw body for every request and reject anything that fails — never gate the check on a field taken from the untrusted body.",
        evidence,
      };
    }
  }
  return null;
}
