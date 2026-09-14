// Passive TLS/certificate posture check. A black-box GET tells us HTTP-vs-HTTPS
// (that is server/findings.ts's "Insecure Connection Protocol" finding), but not
// whether the HTTPS a site DOES serve is actually healthy: an expired
// certificate or a deprecated protocol version is invisible to a plain fetch
// (undici/Node negotiate happily and, with rejectUnauthorized off, don't even
// surface an expired cert). This opens one TLS handshake to the target and
// inspects the negotiated protocol + peer certificate directly.
//
// Read-only and bounded (a single handshake, then the socket is closed). It
// honours the same SSRF discipline as guardedFetch: resolve the host, refuse any
// answer that maps to an internal address, and connect to the VALIDATED IP with
// SNI — so a DNS-rebinding resolver can't answer public to the check and point
// the socket inward.
import tls from "node:tls";
import { resolveIpv4, firstBlockedAddress, isDevAllowedHostname } from "./ssrf.js";
import type { Severity } from "../src/types.js";

export interface TlsObservation {
  // Whether a check was attempted at all (HTTPS targets only).
  checked: boolean;
  // Whether the handshake actually completed.
  reachable: boolean;
  protocol?: string; // negotiated protocol, e.g. "TLSv1.2" / "TLSv1.3"
  validToMs?: number; // certificate notAfter, ms epoch
  subject?: string; // cert subject CN
  issuer?: string; // cert issuer CN
}

export interface TlsIssue {
  kind: "expired" | "expiring-soon" | "deprecated-protocol";
  severity: Severity;
  title: string;
  description: string;
  fix: string;
}

// Renew-window: inside this many days to expiry we flag it, so an operator hears
// about it before the outage rather than after.
const EXPIRING_SOON_DAYS = 21;
// TLS 1.2 is the current minimum baseline; anything below it is deprecated and
// dropped by modern browsers. Node reports these exact strings from getProtocol().
const DEPRECATED_PROTOCOLS = new Set(["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]);

// A certificate CN can be a string or (rarely) an array in Node's types; fold to
// a single display string.
function cnToString(cn: string | string[] | undefined): string | undefined {
  if (Array.isArray(cn)) return cn[0];
  return cn || undefined;
}

// Pure classifier — no network — so the false-positive-critical decisions
// (expired vs. expiring vs. fine; deprecated vs. current) are unit-testable.
export function classifyTls(obs: TlsObservation, nowMs = Date.now()): TlsIssue[] {
  const issues: TlsIssue[] = [];
  if (!obs.checked || !obs.reachable) return issues;

  if (typeof obs.validToMs === "number" && Number.isFinite(obs.validToMs)) {
    const days = Math.floor((obs.validToMs - nowMs) / 86_400_000);
    const until = new Date(obs.validToMs).toUTCString();
    if (days < 0) {
      issues.push({
        kind: "expired",
        severity: "high",
        title: "Expired TLS Certificate",
        description: `The TLS certificate${obs.subject ? ` for ${obs.subject}` : ""} expired ${Math.abs(days)} day(s) ago (valid until ${until}). Browsers show a full-page security interstitial and any client that verifies certificates refuses to connect — an effective outage as well as a trust failure.`,
        fix: "Renew the TLS certificate immediately and automate renewal (e.g. certbot, or your host's managed certificates) so it cannot lapse again.",
      });
    } else if (days <= EXPIRING_SOON_DAYS) {
      issues.push({
        kind: "expiring-soon",
        severity: days <= 7 ? "medium" : "low",
        title: "TLS Certificate Expiring Soon",
        description: `The TLS certificate expires in ${days} day(s) (valid until ${until}). If it lapses, browsers will block the site with a security warning.`,
        fix: "Renew the certificate now and enable automatic renewal so it never reaches this window.",
      });
    }
  }

  if (obs.protocol && DEPRECATED_PROTOCOLS.has(obs.protocol)) {
    issues.push({
      kind: "deprecated-protocol",
      severity: "medium",
      title: `Deprecated TLS Protocol (${obs.protocol})`,
      description: `The server negotiated ${obs.protocol}, a deprecated protocol with known weaknesses (BEAST/POODLE-class attacks) that modern browsers have dropped. TLS 1.2 is the current minimum baseline and TLS 1.3 is preferred.`,
      fix: "Disable TLS 1.1 and earlier at the web server or load balancer and require TLS 1.2 or higher (add TLS 1.3 where available).",
    });
  }

  return issues;
}

// Open one handshake to the target and read protocol + certificate. Never
// throws; returns { checked, reachable:false } on any failure so a TLS hiccup
// can't fail the scan.
export async function probeTls(targetUrl: string, timeoutMs = 6000): Promise<TlsObservation> {
  let u: URL;
  try {
    u = new URL(targetUrl);
  } catch {
    return { checked: false, reachable: false };
  }
  if (u.protocol !== "https:") return { checked: false, reachable: false };

  const host = u.hostname;
  const port = Number(u.port) || 443;

  // SSRF gate, mirroring guardedFetch: connect to a validated IP, never a name a
  // rebinding resolver could re-point between the check and the socket.
  let ip: string;
  if (isDevAllowedHostname(host)) {
    ip = host;
  } else {
    const addrs = await resolveIpv4(host).catch(() => [] as string[]);
    if (!addrs.length) return { checked: true, reachable: false };
    if (firstBlockedAddress(host, addrs)) return { checked: true, reachable: false };
    ip = addrs[0];
  }

  return await new Promise<TlsObservation>((resolve) => {
    let settled = false;
    const done = (obs: TlsObservation) => {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch { /* already closed */ }
      resolve(obs);
    };
    // rejectUnauthorized:false so we can still INSPECT an expired/mismatched cert
    // (that's the point) rather than the handshake aborting before we read it.
    const socket = tls.connect(
      { host: ip, servername: host, port, timeout: timeoutMs, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol() || undefined;
        const validToMs = cert && cert.valid_to ? Date.parse(cert.valid_to) : undefined;
        done({
          checked: true,
          reachable: true,
          protocol,
          validToMs: typeof validToMs === "number" && Number.isFinite(validToMs) ? validToMs : undefined,
          subject: cnToString(cert && cert.subject ? cert.subject.CN : undefined),
          issuer: cnToString(cert && cert.issuer ? cert.issuer.CN : undefined),
        });
      },
    );
    socket.on("error", () => done({ checked: true, reachable: false }));
    socket.on("timeout", () => done({ checked: true, reachable: false }));
  });
}
