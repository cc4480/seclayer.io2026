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

// Best-effort synchronous block of obviously-internal request hosts inside the
// browser (defense in depth; rendering should run in an egress-restricted env).
function hostLooksInternal(hostname: string): boolean {
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
