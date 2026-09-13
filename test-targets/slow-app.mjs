// A deliberately SLOW, clean target for capacity testing.
//
// hardened-app.mjs answers instantly, which makes a scan finish in well under a
// second. At that speed a scan is over before the next one starts, so the
// measured concurrency is always ~1 and the concurrency cap is never actually
// exercised — the load test reports a queueing bottleneck that is really just
// the fixture being unrealistically fast.
//
// Real scans against real sites take tens of seconds, dominated by waiting on
// the network. This reproduces that shape: every response is delayed, so scans
// overlap and the worker's concurrency limit becomes the thing under test.
//
// The delay is a SLEEP, not work: it holds a scan slot without consuming CPU,
// which is exactly how a real scan spends most of its life. That keeps the RSS
// figure meaningful — it measures the memory a held scan slot costs, which is
// the number that decides how high concurrency can safely go.
import http from "node:http";

const port = Number(process.argv[2] || 4102);
const delayMs = Number(process.env.SLOW_DELAY_MS || 400);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const PAGE = `<!doctype html>
<html><head><title>Capacity fixture</title>
<meta http-equiv="Content-Security-Policy" content="default-src 'self'">
</head><body>
<h1>Capacity test fixture</h1>
<p>Clean by construction: no secrets, no inline script, no forms.</p>
<a href="/about">About</a> <a href="/contact">Contact</a> <a href="/docs">Docs</a>
</body></html>`;

http
  .createServer(async (req, res) => {
    await sleep(delayMs);
    // Hardened headers, so a scan of this fixture reports nothing and the run
    // measures capacity rather than finding-handling.
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "X-Frame-Options": "DENY",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
      "Content-Security-Policy": "default-src 'self'",
      "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    });
    res.end(PAGE);
  })
  .listen(port, "127.0.0.1", () => {
    console.log(`[slow-app] 127.0.0.1:${port} — every response delayed ${delayMs}ms`);
  });
