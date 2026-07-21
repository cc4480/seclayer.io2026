// EASM perimeter mapping and sensitive-path probing. Resolves the target's real
// host IP and authoritative nameserver, enumerates common subdomains (wildcard-
// DNS aware so wildcards don't bloat the results with false positives), and
// probes a small set of high-value sensitive paths — treating one as "exposed"
// only when the response BODY matches the file's signature, not merely on a 200.
// Mutates the passed DiagnosticResult in place (easmPerimeter + probedPaths).
import type { DiagnosticResult } from "./scanner.js";
import { safeFetch } from "./ssrf.js";
import { looksLikeHtml } from "./evidence.js";
import crypto from "crypto";
import * as dns from "dns/promises";

const COMMON_SUBDOMAINS = [
  "www", "api", "dev", "staging", "admin", "vpn", "dashboard", "status", "mail",
  "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure", "shop",
  "portal", "test", "cdn", "app", "m", "cloud", "qa", "support", "docs", "help",
  "login", "auth", "ftp", "pop", "imap",
];

export async function scanPerimeter(host: string, hostname: string, result: DiagnosticResult): Promise<void> {
  // EASM: DNS + subdomain enumeration.
  try {
    const ipRecords = await dns.resolve4(hostname).catch(() => []);
    if (ipRecords && ipRecords.length > 0) {
      result.easmPerimeter.ip = ipRecords[0];
    }

    // Resolve the authoritative nameserver(s) for real, when available.
    const nsRecords = await dns.resolveNs(hostname).catch(() => [] as string[]);
    if (nsRecords && nsRecords.length > 0) {
      result.easmPerimeter.nameserver = nsRecords[0];
    }

    // Check for Wildcard DNS to prevent false positive subdomain bloating
    let wildcardIp: string | null = null;
    try {
      const randomSub = crypto.randomBytes(6).toString("hex");
      const wildcardRecords = await dns.resolve4(`${randomSub}.${hostname}`);
      if (wildcardRecords && wildcardRecords.length > 0) {
        wildcardIp = wildcardRecords[0];
      }
    } catch (e) {
      // No wildcard DNS detected
    }

    const subdomainChecks = COMMON_SUBDOMAINS.map(async (sub) => {
      const subUrl = `${sub}.${hostname}`;
      try {
        const records = await dns.resolve4(subUrl);

        // Filter out false positives caused by Wildcard DNS records
        if (wildcardIp && records.includes(wildcardIp)) {
          return { domain: subUrl, status: "inactive" as const, port: "0" };
        }

        return {
          domain: subUrl,
          status: "live" as const,
          port: sub.includes("vpn")
            ? "1194"
            : sub.includes("mail") || sub.includes("smtp")
              ? "25"
              : "443",
          ip: records[0],
        };
      } catch (err) {
        return { domain: subUrl, status: "inactive" as const, port: "0" };
      }
    });

    const subResults = await Promise.all(subdomainChecks);
    result.easmPerimeter.subdomains = subResults;
  } catch (e) {
    console.warn("DNS resolution failed or not supported in this environment.", e);
    // Fallback
    COMMON_SUBDOMAINS.slice(0, 10).forEach((sub) => {
      result.easmPerimeter.subdomains.push({
        domain: `${sub}.${hostname}`,
        status: "inactive",
        port: "0",
      });
    });
  }

  // Sensitive Paths Probing. A path is only treated as "exposed" when the
  // response BODY actually matches the file's signature, not merely on a 200.
  // This eliminates the dominant false positive: single-page apps that serve
  // index.html (HTTP 200) for every unknown path including /.env.
  const sensitiveProbes: Array<{ path: string; matches: (body: string) => boolean }> = [
    { path: "/.env", matches: (b) => !looksLikeHtml(b) && /^[A-Z][A-Z0-9_]*\s*=/m.test(b) },
    { path: "/.git/config", matches: (b) => /\[core\]/i.test(b) || /repositoryformatversion/i.test(b) },
    { path: "/.git/HEAD", matches: (b) => /^ref:\s+refs\//m.test(b.trim()) },
    { path: "/phpinfo.php", matches: (b) => /<title>phpinfo\(\)/i.test(b) || /PHP Version\s*</i.test(b) },
    { path: "/.aws/credentials", matches: (b) => !looksLikeHtml(b) && /aws_access_key_id/i.test(b) },
    { path: "/config.json", matches: (b) => !looksLikeHtml(b) && /"(password|secret|api[_-]?key|private[_-]?key)"\s*:/i.test(b) },
  ];

  for (const probe of sensitiveProbes) {
    try {
      const probeController = new AbortController();
      const probeId = setTimeout(() => probeController.abort(), 2500);
      const probeRes = await safeFetch(`${host}${probe.path}`, {
        method: "GET",
        headers: { "User-Agent": "Seclayer-Security-Scanner/2.0 (seclayer.io)" },
        signal: probeController.signal,
      });
      const body = await probeRes.text().catch(() => "");
      clearTimeout(probeId);

      const exposed = probeRes.status === 200 && probe.matches(body);
      result.probedPaths.push({ path: probe.path, status: probeRes.status, exposed });
    } catch (err) {
      result.probedPaths.push({ path: probe.path, status: 0, exposed: false });
    }
  }
}
