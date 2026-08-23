// EASM perimeter mapping and sensitive-path probing. Resolves the target's real
// host IP and authoritative nameserver, enumerates common subdomains (wildcard-
// DNS aware so wildcards don't bloat the results with false positives), and
// probes a small set of high-value sensitive paths — treating one as "exposed"
// only when the response BODY matches the file's signature, not merely on a 200.
// Mutates the passed DiagnosticResult in place (easmPerimeter + probedPaths).
import type { DiagnosticResult } from "./scanner.js";
import type { Severity } from "../src/types.js";
import { safeFetch } from "./ssrf.js";
import { looksLikeHtml } from "./evidence.js";
import crypto from "crypto";
import * as dns from "dns/promises";

// One sensitive-path check. A path is "exposed" only when the response BODY
// matches `matches` (never a status code alone), which eliminates the dominant
// false positive: SPAs that serve index.html (HTTP 200) for every unknown path.
// `meta`, when present, carries this file's own finding wording + severity;
// absent → findings.ts applies its generic critical/high exposed-file mapping.
export interface SensitiveProbe {
  path: string;
  matches: (body: string) => boolean;
  meta?: { title: string; severity: Severity; description: string; fix: string };
}

// Exported so the signature matchers are unit-testable without a live target.
export const SENSITIVE_PROBES: SensitiveProbe[] = [
  // --- Secret / VCS / config files (critical–high, via the default mapping) ---
  { path: "/.env", matches: (b) => !looksLikeHtml(b) && /^[A-Z][A-Z0-9_]*\s*=/m.test(b) },
  { path: "/.git/config", matches: (b) => /\[core\]/i.test(b) || /repositoryformatversion/i.test(b) },
  { path: "/.git/HEAD", matches: (b) => /^ref:\s+refs\//m.test(b.trim()) },
  { path: "/phpinfo.php", matches: (b) => /<title>phpinfo\(\)/i.test(b) || /PHP Version\s*</i.test(b) },
  { path: "/.aws/credentials", matches: (b) => !looksLikeHtml(b) && /aws_access_key_id/i.test(b) },
  { path: "/config.json", matches: (b) => !looksLikeHtml(b) && /"(password|secret|api[_-]?key|private[_-]?key)"\s*:/i.test(b) },

  // --- Supply-chain: dependency lockfiles ---
  // A lockfile discloses the EXACT resolved version of every direct and
  // transitive dependency, letting an attacker map the app to known CVEs offline
  // with no guesswork. Real exposure, but not a breach on its own → LOW.
  {
    path: "/package-lock.json",
    matches: (b) => !looksLikeHtml(b) && /"lockfileVersion"\s*:/.test(b),
    meta: {
      title: "Exposed npm lockfile (package-lock.json)",
      severity: "low",
      description: "The npm lockfile package-lock.json is publicly served. It discloses the exact resolved version of every direct and transitive dependency, which an attacker uses to map the application to known-vulnerable package versions (CVEs) with no guesswork.",
      fix: "Don't serve lockfiles from the web root — they belong in source control and the build environment, not the deployed public directory. Exclude package-lock.json (and yarn.lock / pnpm-lock.yaml) from the served build output.",
    },
  },
  {
    path: "/yarn.lock",
    matches: (b) => !looksLikeHtml(b) && (/^# yarn lockfile v1/m.test(b) || /^__metadata:/m.test(b)),
    meta: {
      title: "Exposed Yarn lockfile (yarn.lock)",
      severity: "low",
      description: "The Yarn lockfile yarn.lock is publicly served, disclosing the exact resolved version of every dependency — enough to map the app to known-vulnerable versions (CVEs) offline.",
      fix: "Exclude yarn.lock from the deployed public directory; keep it in source control only.",
    },
  },
  {
    path: "/pnpm-lock.yaml",
    matches: (b) => !looksLikeHtml(b) && /^lockfileVersion:/m.test(b),
    meta: {
      title: "Exposed pnpm lockfile (pnpm-lock.yaml)",
      severity: "low",
      description: "The pnpm lockfile pnpm-lock.yaml is publicly served, disclosing the exact resolved version of every dependency — enough to map the app to known-vulnerable versions (CVEs) offline.",
      fix: "Exclude pnpm-lock.yaml from the deployed public directory; keep it in source control only.",
    },
  },
  {
    path: "/composer.lock",
    matches: (b) => !looksLikeHtml(b) && /"content-hash"\s*:/.test(b),
    meta: {
      title: "Exposed Composer lockfile (composer.lock)",
      severity: "low",
      description: "The PHP Composer lockfile composer.lock is publicly served, disclosing the exact resolved version of every PHP dependency — enough to map the app to known-vulnerable versions (CVEs) offline.",
      fix: "Serve only the application's public/ directory; keep composer.lock out of the web root.",
    },
  },
  {
    path: "/Gemfile.lock",
    matches: (b) => !looksLikeHtml(b) && /^GEM$/m.test(b) && /^DEPENDENCIES$/m.test(b),
    meta: {
      title: "Exposed Ruby lockfile (Gemfile.lock)",
      severity: "low",
      description: "The Ruby Bundler lockfile Gemfile.lock is publicly served, disclosing the exact resolved version of every gem — enough to map the app to known-vulnerable versions (CVEs) offline.",
      fix: "Exclude Gemfile.lock from the public web root; keep it in source control only.",
    },
  },
  // A published .npmrc carrying an auth token is a CREDENTIAL leak, not mere
  // dependency disclosure — an npm registry token grants supply-chain WRITE
  // access. HIGH, and only fired when a token is actually present.
  {
    path: "/.npmrc",
    matches: (b) => !looksLikeHtml(b) && /_authToken\s*=/.test(b),
    meta: {
      title: "Exposed npm credentials (.npmrc auth token)",
      severity: "high",
      description: "A publicly served .npmrc contains an _authToken — a live npm registry credential. Anyone can read it and use it to publish or unpublish packages under the associated account, a direct supply-chain compromise vector.",
      fix: "Rotate the leaked token immediately (npm token revoke), remove .npmrc from anything served publicly, and supply registry auth via a CI secret / environment variable instead of a committed file.",
    },
  },
];

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
  // index.html (HTTP 200) for every unknown path including /.env. See
  // SENSITIVE_PROBES above (secret/VCS/config files + supply-chain lockfiles).
  for (const probe of SENSITIVE_PROBES) {
    try {
      const probeController = new AbortController();
      const probeId = setTimeout(() => probeController.abort(), 2500);
      const probeRes = await safeFetch(`${host}${probe.path}`, {
        method: "GET",
        headers: { "User-Agent": "Seclayer-Security-Scanner/2.0 (seclayerio.ai)" },
        signal: probeController.signal,
      });
      const body = await probeRes.text().catch(() => "");
      clearTimeout(probeId);

      const exposed = probeRes.status === 200 && probe.matches(body);
      // Retain the body only when actually exposed (capped — these are
      // small config-shaped files, not arbitrary large responses) so
      // downstream checks (e.g. leaked-secret/credential extraction in
      // server/jwtProbe.ts, server/credentialChainProbe.ts) can inspect what
      // this probe already fetched, instead of every such check needing its
      // own separate request to the same sensitive path.
      result.probedPaths.push({
        path: probe.path,
        status: probeRes.status,
        exposed,
        ...(exposed ? { body: body.slice(0, 50_000) } : {}),
        // Attach this file's own finding wording/severity when it defines one
        // (e.g. lockfiles → LOW), so findings.ts doesn't apply the generic
        // critical/high exposed-file mapping meant for secret/VCS files.
        ...(exposed && probe.meta ? { meta: probe.meta } : {}),
      });
    } catch (err) {
      result.probedPaths.push({ path: probe.path, status: 0, exposed: false });
    }
  }
}
