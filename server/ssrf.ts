// SSRF protection + the SSRF-safe fetch primitives.
//
// The scanner issues server-side HTTP requests to user-supplied targets, so it
// must refuse internal/reserved destinations (loopback, RFC1918, link-local,
// cloud metadata, CGNAT, etc.) to avoid being abused as an SSRF proxy. Every
// server-side request to a user-controlled host (scan target, alert webhook,
// domain-verification file) MUST go through guardedFetch/safeFetch so it is
// bound to the validating dispatcher below.
import net from "net";
import * as dns from "dns/promises";
import { Agent } from "undici";

export function isBlockedIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    if (a === 0) return true; // "this" network
    if (a === 127) return true; // loopback
    if (a === 10) return true; // private
    if (a === 172 && b >= 16 && b <= 31) return true; // private
    if (a === 192 && b === 168) return true; // private
    if (a === 169 && b === 254) return true; // link-local + cloud metadata
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a >= 224) return true; // multicast / reserved
    return false;
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === "::1" || lower === "::") return true; // loopback / unspecified
    if (lower.startsWith("fe80")) return true; // link-local
    if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // unique local
    const mapped = lower.match(/::ffff:(\d+\.\d+\.\d+\.\d+)/); // IPv4-mapped
    if (mapped) return isBlockedIp(mapped[1]);
    return false;
  }
  return true; // unrecognized format -> block
}

// Dev-only, opt-in escape hatch for scanning a LOCAL target on this machine
// (e.g. an intentionally-vulnerable test app) so the active-probe pipeline can
// be exercised against infrastructure the operator owns. HARD-disabled in
// production, off unless SCAN_DEV_ALLOW_HOSTS lists the exact host[:port]
// (comma-separated, e.g. "127.0.0.1:4100"). This is the ONLY way the SSRF guard
// yields an internal address, and only for a hand-listed loopback test target.
function isDevAllowedHost(parsedUrl: URL): boolean {
  if (process.env.NODE_ENV === "production") return false;
  const allow = (process.env.SCAN_DEV_ALLOW_HOSTS || "")
    .split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (allow.length === 0) return false;
  const host = parsedUrl.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const port = parsedUrl.port || (parsedUrl.protocol === "https:" ? "443" : "80");
  return allow.includes(`${host}:${port}`) || allow.includes(host);
}

// Hostname-level view of the dev allowlist. The connect-time DNS lookup only
// sees a hostname (never a port), so this matches on the host part alone; a
// listed loopback test target still connects in dev. Hard-off in production,
// exactly like isDevAllowedHost. Exported for non-HTTP consumers (e.g.
// server/nmap/resolve.ts) that need the same bypass outside guardedFetch.
export function isDevAllowedHostname(hostname: string): boolean {
  if (process.env.NODE_ENV === "production") return false;
  const allow = (process.env.SCAN_DEV_ALLOW_HOSTS || "")
    .split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (allow.length === 0) return false;
  const h = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return allow.some((entry) => entry === h || entry.split(":")[0] === h);
}

// The rebinding-guard decision, isolated so it can be unit-tested without a live
// resolver: given the addresses a host actually resolved to, return the first
// one that must be refused (honoring the dev allowlist), or null if all are
// safe. A single internal answer among otherwise-public ones — the shape of a
// DNS-rebinding response — is enough to refuse the whole connection.
export function firstBlockedAddress(hostname: string, addresses: string[]): string | null {
  if (isDevAllowedHostname(hostname)) return null;
  for (const a of addresses) if (isBlockedIp(a)) return a;
  return null;
}

// --- SSRF-safe dispatcher (closes the DNS-rebinding TOCTOU) -------------------
// The pre-flight assertTargetIsScannable() resolves and validates the host, but
// the socket layer then resolves it AGAIN independently — so a hostile resolver
// that returns a public IP to the check and an internal IP to the connection
// (DNS rebinding) can slip past. This dispatcher removes that gap: it performs
// the resolution ITSELF inside the connect lookup, validates every address with
// isBlockedIp, and hands the socket only vetted IPs. The validated lookup IS the
// connect lookup — there is no second, unchecked resolution — so a rebinding
// answer can never reach connect().
export const safeDispatcher = new Agent({
  connect: {
    lookup(
      hostname: string,
      options: any,
      cb: (err: NodeJS.ErrnoException | null, address?: any, family?: number) => void,
    ) {
      const finish = (addrs: Array<{ address: string; family: number }>) => {
        const blocked = firstBlockedAddress(hostname, addrs.map((a) => a.address));
        if (blocked) {
          return cb(
            Object.assign(
              new Error(
                `Refusing to connect: "${hostname}" resolves to blocked internal address ${blocked}`,
              ),
              { code: "ESSRFBLOCKED" },
            ),
          );
        }
        // undici calls lookup with { all: true } and expects an address array;
        // support the single-address callback form too for completeness.
        return options && options.all
          ? cb(null, addrs as any)
          : cb(null, addrs[0].address, addrs[0].family);
      };
      // IP literals never reach the lookup (net connects directly) and are
      // validated by assertTargetIsScannable; handled here only defensively.
      if (net.isIP(hostname)) {
        return finish([{ address: hostname, family: net.isIPv6(hostname) ? 6 : 4 }]);
      }
      Promise.all([
        dns.resolve4(hostname).catch(() => [] as string[]),
        dns.resolve6(hostname).catch(() => [] as string[]),
      ])
        .then(([v4, v6]) => {
          const addrs = [
            ...v4.map((address) => ({ address, family: 4 })),
            ...v6.map((address) => ({ address, family: 6 })),
          ];
          if (addrs.length === 0) return cb(new Error(`DNS resolution failed for ${hostname}`));
          finish(addrs);
        })
        .catch((e) => cb(e));
    },
  },
});

// The one SSRF-safe fetch primitive. Identical to fetch() but pinned to the
// validating dispatcher above, so the connection can never be rebound onto an
// internal address between the guard and the socket. It does NOT follow
// redirects on its own — callers set `redirect` as they need; safeFetch layers
// per-hop re-validation on top for the multi-hop scan path.
export function guardedFetch(url: string, options: RequestInit = {}): Promise<Response> {
  return fetch(url, { ...options, dispatcher: safeDispatcher } as any);
}

export async function assertTargetIsScannable(parsedUrl: URL): Promise<void> {
  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    throw new Error(
      `Unsupported protocol "${parsedUrl.protocol}". Only http(s) targets can be scanned.`,
    );
  }

  // Dev-only allowlisted local target (never reachable in production).
  if (isDevAllowedHost(parsedUrl)) return;

  const hostname = parsedUrl.hostname.replace(/^\[|\]$/g, ""); // strip IPv6 brackets
  const lower = hostname.toLowerCase();

  // Block internal-only hostnames that may resolve via split-horizon DNS.
  if (
    lower === "localhost" ||
    lower.endsWith(".localhost") ||
    lower.endsWith(".local") ||
    lower.endsWith(".internal")
  ) {
    throw new Error(`Refusing to scan internal hostname "${hostname}".`);
  }

  // Literal IP targets are validated directly.
  if (net.isIP(hostname)) {
    if (isBlockedIp(hostname)) {
      throw new Error(`Refusing to scan internal or reserved address "${hostname}".`);
    }
    return;
  }

  // Otherwise resolve and validate every address the host maps to.
  const [v4, v6] = await Promise.all([
    dns.resolve4(hostname).catch(() => [] as string[]),
    dns.resolve6(hostname).catch(() => [] as string[]),
  ]);
  for (const ip of [...v4, ...v6]) {
    if (isBlockedIp(ip)) {
      throw new Error(
        `Target "${hostname}" resolves to a blocked internal address (${ip}); scan refused.`,
      );
    }
  }
}

// Public boundary check: validates a raw target string the same way
// runDiagnostics normalizes it, so callers can reject SSRF/malformed targets
// before spending credits or enqueuing work. Throws with a user-facing message.
export async function assertScanTargetSafe(targetUrl: string): Promise<void> {
  let url = (targetUrl || "").trim();
  if (!/^https?:\/\//i.test(url)) {
    // Reject explicit non-HTTP schemes (e.g. ftp://, file://, gopher://)
    // rather than silently coercing them into a bogus https host.
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) {
      throw new Error(
        `Unsupported protocol in "${targetUrl}". Only http(s) targets can be scanned.`,
      );
    }
    url = "https://" + url;
  }
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`"${targetUrl}" is not a valid URL.`);
  }
  await assertTargetIsScannable(parsed);
}

// Follows redirects manually, re-validating every hop against the SSRF guard so
// a target cannot 30x-redirect the scanner into internal infrastructure.
export async function safeFetch(targetUrl: string, options: RequestInit, maxRedirects = 4): Promise<Response> {
  let current = targetUrl;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    await assertTargetIsScannable(new URL(current));
    const res = await guardedFetch(current, { ...options, redirect: "manual" });
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      if (loc) {
        current = new URL(loc, current).toString();
        continue;
      }
    }
    return res;
  }
  throw new Error(`Exceeded ${maxRedirects} redirects while scanning ${targetUrl}`);
}
