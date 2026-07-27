// Single-finding fix verification ("retest"). A PROVEN finding carries a
// replayable receipt: the exact request we sent and the literal proof signal we
// found in the response. Retest re-issues that one request through the same
// SSRF-guarded fetch and checks whether the proof signal is still there — a
// cheap, single-request "did my fix work?" that never re-runs a whole scan (and
// so costs no credit). Heuristic (non-proven) and blind out-of-band findings
// can't be replayed inline and are reported as unsupported.
import type { Finding, Scan } from "../src/types.js";
import { guardedFetch, parseAuthHeader } from "./scanner.js";

export interface RetestResult {
  // still_present: the proof signal reproduced → not fixed.
  // not_reproduced: the signal is gone (or the target didn't respond) → likely fixed.
  // unsupported: no replayable inline receipt (heuristic or out-of-band finding).
  status: "still_present" | "not_reproduced" | "unsupported";
  message: string;
  checkedUrl?: string;
}

// Reconstruct the original request from the receipt WE authored via
// evidence.renderRawRequest, so parsing stays robust (we control the format):
//   METHOD /path?query HTTP/1.1
//   Host: <host>
//   <headers>
//   <blank line>
//   <body?>
export function parseAttack(
  request: string,
  scanUrl: string,
): { method: string; url: string; contentType?: string; body?: string } | null {
  const lines = request.split("\n");
  const first = lines[0]?.split(" ");
  if (!first || first.length < 2) return null;
  const method = first[0].toUpperCase();
  const pathQuery = first[1];

  let host = "";
  let contentType: string | undefined;
  let i = 1;
  for (; i < lines.length; i++) {
    if (lines[i] === "") { i++; break; }
    const idx = lines[i].indexOf(":");
    if (idx > 0) {
      const name = lines[i].slice(0, idx).trim().toLowerCase();
      const val = lines[i].slice(idx + 1).trim();
      if (name === "host") host = val;
      else if (name === "content-type") contentType = val;
    }
  }
  if (!host) return null;
  const body = i < lines.length ? lines.slice(i).join("\n") : undefined;

  let scheme = "https";
  try { scheme = new URL(scanUrl).protocol.replace(":", ""); } catch { /* default https */ }
  return { method, url: `${scheme}://${host}${pathQuery}`, contentType, body: body || undefined };
}

export async function retestFinding(finding: Finding, scan: Scan): Promise<RetestResult> {
  const ev = finding.evidence;
  const quote = ev?.signal?.quote;
  if (!ev || !ev.attack?.request || !quote) {
    return {
      status: "unsupported",
      message: "This finding has no replayable exploit receipt, so it can't be auto-verified. Re-run a full scan to re-check it.",
    };
  }
  if (ev.method === "out-of-band") {
    return {
      status: "unsupported",
      message: "Blind (out-of-band) findings are proven by a collaborator callback, not an inline response, so they can't be replayed from the receipt. Re-run a full scan to re-verify.",
    };
  }

  const attack = parseAttack(ev.attack.request, scan.url);
  if (!attack) {
    return { status: "unsupported", message: "Could not reconstruct the original request from the receipt. Re-run a full scan to re-verify." };
  }

  const headers: Record<string, string> = {
    "User-Agent": "Seclayer-Security-Scanner/2.0 (fix-verification)",
    ...parseAuthHeader(scan.authHeader),
  };
  if (attack.contentType) headers["Content-Type"] = attack.contentType;

  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 8000);
  try {
    const res = await guardedFetch(attack.url, {
      method: attack.method,
      headers,
      body: attack.method === "GET" || attack.method === "HEAD" ? undefined : attack.body,
      // Don't follow redirects: the open-redirect / CRLF proofs live in the 3xx
      // Location / injected response headers, exactly as originally captured.
      redirect: "manual",
      signal: ctl.signal,
    });
    const bodyText = await res.text().catch(() => "");
    // Search the same surfaces the original proof came from: status line,
    // response headers (open-redirect/CRLF/CORS proofs), and the body.
    let headerDump = `${res.status} ${res.statusText}\n`;
    res.headers.forEach((v, k) => { headerDump += `${k}: ${v}\n`; });
    const haystack = `${headerDump}\n${bodyText}`;

    return haystack.includes(quote)
      ? { status: "still_present", message: "Still vulnerable — the original proof signal is still present in the response.", checkedUrl: attack.url }
      : { status: "not_reproduced", message: "The exploit no longer reproduces — the proof signal is gone. It looks fixed. Run a full scan to confirm across the whole surface.", checkedUrl: attack.url };
  } catch (e: any) {
    // A failed request means the exploit did not reproduce (the endpoint may now
    // reject the payload); report it as not-reproduced with the reason.
    return {
      status: "not_reproduced",
      message: `The exploit did not reproduce — the request failed or the target didn't respond (${e?.message || "error"}). Run a full scan to confirm.`,
      checkedUrl: attack.url,
    };
  } finally {
    clearTimeout(timer);
  }
}
