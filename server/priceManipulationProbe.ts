// Business-logic price-tampering probe (AGGRESSIVE tier). Proves a checkout /
// order endpoint bills whatever unit price the CLIENT sends, instead of looking
// the price up server-side — the canonical "trust the client's price" flaw.
//
// The proof is a differential that is BOTH accurate and non-destructive:
//   * Two requests are sent that differ ONLY in the unit price, each with a
//     distinctive quantity>1. If the server's returned charge total equals
//     price*quantity in BOTH (a COMPUTED product, at the same response field),
//     the endpoint is computing the bill from the client's price. Requiring the
//     product (not just the echoed price back) is what rules out a plain "echo
//     my input" endpoint — an echo reflects the price but never price*quantity.
//   * It sends NO payment credentials and NO confirmation/commit signal — only
//     line items — so on any correctly-layered checkout it can elicit at most a
//     quote/total, never a completed charge (a real charge needs a payment
//     instrument + a confirm step this probe never provides). Gated to the
//     aggressive + ownership-verified tier like the other active-mutation-shaped
//     probes.
import { safeFetch } from "./ssrf.js";
import type { RedTeamFinding } from "./scanTypes.js";
import type { ExploitEvidence } from "../src/types.js";
import { renderRawRequest } from "./evidence.js";

// Distinctive unit prices + a quantity>1 so the oracle keys on a COMPUTED
// product (price*QTY), never a bare echoed price. Values chosen to multiply
// cleanly and be astronomically unlikely to appear by coincidence.
const QTY = 3;
const PRICE_A = 7.0;   // → product 21
const PRICE_B = 953.0; // → product 2859
const bodyFor = (price: number) => JSON.stringify({ items: [{ price, quantity: QTY }] });

// Targeted guess list (not a wordlist) of common checkout/order endpoints,
// mirroring COMMON_PROTECTED_PATHS' "curated candidates, not brute force" style.
const CHECKOUT_PATHS = [
  "/api/checkout", "/api/cart", "/api/order", "/api/orders", "/api/purchase",
  "/api/payment", "/api/pay", "/checkout", "/api/billing/checkout", "/api/order/create",
];

const approxEq = (a: number, b: number) => Math.abs(a - b) < 0.005;

// Flatten a JSON value to { dotted.path: finiteNumber } for every numeric leaf.
function collectNumbers(obj: unknown, prefix = "", out: Record<string, number> = {}): Record<string, number> {
  if (obj && typeof obj === "object") {
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      const path = prefix ? `${prefix}.${k}` : k;
      if (typeof v === "number" && Number.isFinite(v)) out[path] = v;
      else if (v && typeof v === "object") collectNumbers(v, path, out);
    }
  }
  return out;
}

async function postJson(url: string, headers: Record<string, string>, body: string): Promise<{ res: Response; text: string }> {
  const ctl = new AbortController();
  const id = setTimeout(() => ctl.abort(), 5000);
  try {
    const res = await safeFetch(url, {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/json" },
      body,
      signal: ctl.signal,
    });
    return { res, text: await res.text().catch(() => "") };
  } finally {
    clearTimeout(id);
  }
}

function parseJson(text: string): unknown {
  try { return JSON.parse(text); } catch { return null; }
}

export async function probePriceManipulation(
  rootUrl: string,
  postUrls: string[],
  headers: Record<string, string>,
): Promise<RedTeamFinding | null> {
  const base = rootUrl.replace(/\/+$/, "");
  const candidates = [...new Set([...CHECKOUT_PATHS.map((p) => `${base}${p}`), ...postUrls])];
  const jsonHeaders = { ...headers, "Content-Type": "application/json" };

  for (const url of candidates) {
    let a: { res: Response; text: string };
    let b: { res: Response; text: string };
    try {
      a = await postJson(url, headers, bodyFor(PRICE_A));
      if (a.res.status >= 400) continue; // not a working checkout-style endpoint here
      b = await postJson(url, headers, bodyFor(PRICE_B));
    } catch {
      continue;
    }
    const numsA = collectNumbers(parseJson(a.text));
    const numsB = collectNumbers(parseJson(b.text));

    // A field that equals price*QTY in BOTH responses = the server computed the
    // bill from the client-supplied price both times.
    const matchPath = Object.keys(numsA).find(
      (p) => approxEq(numsA[p], PRICE_A * QTY) && p in numsB && approxEq(numsB[p], PRICE_B * QTY),
    );
    if (!matchPath) continue;

    const totalB = String(Math.round(PRICE_B * QTY * 100) / 100); // literal substring of response B
    const evidence: ExploitEvidence = {
      method: "differential",
      attack: {
        request: renderRawRequest("POST", url, jsonHeaders, bodyFor(PRICE_B)),
        response: `HTTP/1.1 ${b.res.status} ${b.res.statusText}\n\n` + (b.text.length > 1200 ? b.text.slice(0, 1200) + "\n[…truncated]" : b.text),
      },
      baseline: {
        request: renderRawRequest("POST", url, jsonHeaders, bodyFor(PRICE_A)),
        response: `HTTP/1.1 ${a.res.status} ${a.res.statusText}\n\n` + (a.text.length > 1200 ? a.text.slice(0, 1200) + "\n[…truncated]" : a.text),
      },
      signal: {
        quote: totalB,
        offsetInResponse: b.text.indexOf(totalB) >= 0 ? b.text.indexOf(totalB) : 0,
        why: `The charge total (response field "${matchPath}") equaled the client-supplied unit price × quantity in BOTH requests — ${PRICE_A}×${QTY}=${PRICE_A * QTY} and ${PRICE_B}×${QTY}=${PRICE_B * QTY} — so the server bills whatever price the client sends, rather than sourcing it server-side.`,
      },
      demonstration: `We POSTed a checkout with unit price ${PRICE_A} (qty ${QTY}) and the server charged ${PRICE_A * QTY}; we then sent the same order with unit price ${PRICE_B} and it charged ${PRICE_B * QTY}. The total tracked our client-supplied price both times (field "${matchPath}"), proving the endpoint trusts the client's price instead of looking it up server-side. No payment details or confirmation were sent — this only elicited the server's own computed total.`,
      reproduction: `curl -s -X POST "${url}" -H "Content-Type: application/json" --data '${bodyFor(PRICE_B)}'`,
      capturedAt: new Date().toISOString(),
    };
    return {
      testName: "Business-Logic Price Tampering (client-controlled price honored)",
      payload: bodyFor(PRICE_B),
      severity: "high",
      description:
        "Active aggressive probing proved a business-logic price-tampering flaw: the checkout/order endpoint bills the unit price supplied in the request instead of looking it up server-side. Two orders identical except for the unit price were each charged that exact price × quantity, so an attacker can pay an arbitrary amount (e.g. a fraction of the real price). Proven non-destructively — no payment instrument or order confirmation was submitted, only line items eliciting the server's computed total.",
      fix: "Never trust a client-supplied price. Look each item's price up server-side by product id (for the requested currency/region) and compute the total from that; ignore any price/amount field in the request body. Enforce it again server-side at the payment/charge step.",
      evidence,
    };
  }
  return null;
}
