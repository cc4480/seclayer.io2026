import net from "net";

// Optional headless rendering. Playwright is loaded DYNAMICALLY and only when
// ENABLE_BROWSER_RENDERING=true; if the package or a browser binary is not
// installed it is a graceful no-op. This keeps the default deployment lean
// (no browser in the image, no CI bloat) while letting operators opt in for
// SPA/JS-heavy targets, surfacing client-rendered links and XHR/fetch endpoints
// that static parsing cannot see.

export interface RenderResult {
  html: string; // post-JavaScript DOM
  requestedUrls: string[]; // same-origin URLs the page requested (XHR/fetch/nav)
}

export function isRenderingEnabled(): boolean {
  return process.env.ENABLE_BROWSER_RENDERING === "true";
}

// Target screenshotting is a separate opt-in from crawl rendering: an operator
// may want a visual of the landing page without paying for a full JS crawl of
// every discovered endpoint. Both rely on the same headless browser.
export function isScreenshotEnabled(): boolean {
  return process.env.ENABLE_TARGET_SCREENSHOT === "true";
}

// Best-effort synchronous block of obviously-internal request hosts inside the
// browser (defense in depth; rendering should run in an egress-restricted env).
// Exported so the DOM-XSS probe reuses the exact same SSRF filter.
export function hostLooksInternal(hostname: string): boolean {
  const h = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal")) return true;
  if (net.isIPv4(h)) {
    const [a, b] = h.split(".").map(Number);
    if (a === 127 || a === 10 || a === 0 || a >= 224) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
  }
  if (net.isIPv6(h)) {
    if (h === "::1" || h === "::") return true;
    if (h.startsWith("fe80") || h.startsWith("fc") || h.startsWith("fd")) return true;
  }
  return false;
}

export async function renderPage(
  url: string,
  extraHeaders: Record<string, string>,
  timeoutMs = 12000,
): Promise<RenderResult | null> {
  if (!isRenderingEnabled()) return null;

  let pw: any;
  try {
    // Variable specifier keeps this out of the TS/esbuild dependency graph, so
    // the project builds and runs without playwright installed.
    const pkg = "playwright";
    pw = await import(pkg);
  } catch {
    console.warn('[render] ENABLE_BROWSER_RENDERING is set but "playwright" is not installed; skipping render.');
    return null;
  }

  let browser: any;
  try {
    browser = await pw.chromium.launch({ headless: true, args: ["--no-sandbox", "--disable-dev-shm-usage"] });
    const ctx = await browser.newContext({ extraHTTPHeaders: extraHeaders, ignoreHTTPSErrors: true });
    const page = await ctx.newPage();

    // Block requests to internal hosts and non-http schemes.
    await page.route("**/*", (route: any) => {
      try {
        const u = new URL(route.request().url());
        if ((u.protocol !== "http:" && u.protocol !== "https:") || hostLooksInternal(u.hostname)) {
          return route.abort();
        }
      } catch {
        return route.abort();
      }
      return route.continue();
    });

    const origin = new URL(url).origin;
    const requested = new Set<string>();
    page.on("request", (req: any) => {
      try {
        const u = req.url();
        if (new URL(u).origin === origin) requested.add(u);
      } catch {}
    });

    await page.goto(url, { waitUntil: "networkidle", timeout: timeoutMs }).catch(() => {});
    const html = await page.content().catch(() => "");
    return { html, requestedUrls: [...requested] };
  } catch (err: any) {
    console.warn(`[render] headless render failed: ${err?.message || err}`);
    return null;
  } finally {
    try {
      await browser?.close();
    } catch {}
  }
}

export interface ScreenshotResult {
  dataUri: string; // "data:image/jpeg;base64,…"
  capturedAt: string;
  width: number;
  height: number;
}

// Best-effort visual capture of the target's landing page. Returns null on ANY
// problem (feature disabled, playwright/browser missing, SSRF-blocked host,
// navigation/timeout error) so a capture failure can never fail the scan.
//
// Same SSRF hardening as renderPage(): every request the page makes is filtered
// against hostLooksInternal and non-http schemes, so a redirect or subresource
// cannot pull the browser into internal infrastructure. Should still run in an
// egress-restricted environment as defense in depth.
export async function captureScreenshot(
  url: string,
  extraHeaders: Record<string, string>,
  timeoutMs = 15000,
): Promise<ScreenshotResult | null> {
  if (!isScreenshotEnabled()) return null;

  // Reject non-http(s) and obviously-internal targets before launching anything.
  let origin: string;
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    if (hostLooksInternal(u.hostname)) return null;
    origin = u.origin;
  } catch {
    return null;
  }

  let pw: any;
  try {
    const pkg = "playwright";
    pw = await import(pkg);
  } catch {
    console.warn('[render] ENABLE_TARGET_SCREENSHOT is set but "playwright" is not installed; skipping screenshot.');
    return null;
  }

  const width = 1280;
  const height = 800;
  let browser: any;
  try {
    browser = await pw.chromium.launch({ headless: true, args: ["--no-sandbox", "--disable-dev-shm-usage"] });
    const ctx = await browser.newContext({
      viewport: { width, height },
      extraHTTPHeaders: extraHeaders,
      ignoreHTTPSErrors: true,
      serviceWorkers: "block",
    });
    const page = await ctx.newPage();

    // Block internal hosts and non-http schemes for every request (nav + subresource).
    await page.route("**/*", (route: any) => {
      try {
        const u = new URL(route.request().url());
        if ((u.protocol !== "http:" && u.protocol !== "https:") || hostLooksInternal(u.hostname)) {
          return route.abort();
        }
      } catch {
        return route.abort();
      }
      return route.continue();
    });

    // Refuse to end up on an internal origin after redirects.
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: timeoutMs }).catch(() => {});
    try {
      const landed = new URL(page.url());
      if (hostLooksInternal(landed.hostname)) return null;
    } catch {}

    // Brief settle for above-the-fold content, capped so a slow page can't hang.
    await page.waitForTimeout(Math.min(1500, Math.floor(timeoutMs / 4)));

    // Viewport-only JPEG (not fullPage) to bound the encoded size.
    const buf: Buffer = await page.screenshot({ type: "jpeg", quality: 55, fullPage: false });
    if (!buf || buf.length === 0) return null;

    return {
      dataUri: `data:image/jpeg;base64,${buf.toString("base64")}`,
      capturedAt: new Date().toISOString(),
      width,
      height,
    };
  } catch (err: any) {
    console.warn(`[render] screenshot capture failed: ${err?.message || err}`);
    return null;
  } finally {
    try {
      await browser?.close();
    } catch {}
  }
}
