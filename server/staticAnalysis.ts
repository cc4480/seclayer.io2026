// Static analysis of client-served markup: high-precision secret signatures
// (SAST) and vulnerable-library footprints (SCA). Pure functions over the served
// HTML/JS so they can be unit-tested without a live target. A signature match is
// necessary but not sufficient — secret matches are additionally screened for
// documented example/placeholder credentials (see fpFilters).
import type { DiagnosticResult } from "./scanner.js";
import { Severity } from "../src/types.js";
import { isLikelyPlaceholderSecret } from "./fpFilters.js";

// --- SAST: exposed-credential signatures --------------------------------------
// Only patterns that are essentially never legitimately client-side are reported
// with high confidence. Identifiers that are frequently public by design (e.g.
// Firebase/Maps browser keys) are reported low/medium so they do not become
// false positives.
// Exposed-credential signatures. Module-level so SECRET_SIGNATURE_COUNT can be
// exported for scan-coverage reporting (how many signatures each document is
// screened against).
const SECRET_SIGNATURES = [
    {
      name: "Stripe Secret Key",
      regex: /sk_live_[0-9a-zA-Z]{24,}/,
      severity: "critical" as Severity,
      confidence: "high" as const,
      note: "A Stripe live secret key grants full API access and must never appear client-side.",
    },
    {
      name: "GitHub OAuth Access Token",
      regex: /gho_[a-zA-Z0-9]{36}/,
      severity: "critical" as Severity,
      confidence: "high" as const,
      note: "A GitHub OAuth token grants repository access and must never be shipped to browsers.",
    },
    {
      name: "Private Key Block",
      regex: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
      severity: "critical" as Severity,
      confidence: "high" as const,
      note: "A PEM private key block was served to the client; the corresponding key must be rotated.",
    },
    {
      name: "AWS Access Key ID",
      regex: /AKIA[0-9A-Z]{16}/,
      severity: "high" as Severity,
      confidence: "medium" as const,
      note: "An AWS access key id is exposed. Confirm the matching secret is not also leaked and rotate it.",
    },
    {
      name: "Google API Key",
      regex: /AIzaSy[A-Za-z0-9_\-]{33}/,
      severity: "low" as Severity,
      confidence: "low" as const,
      note: "Google browser API keys are often intentionally public; verify it is restricted by HTTP referrer/API and not a server key.",
    },
  ];
export const SECRET_SIGNATURE_COUNT = SECRET_SIGNATURES.length;

// `source` labels WHERE the text came from — defaults to the historical
// root-document label so every existing caller is unaffected. Callers scanning
// a specific crawled page/endpoint pass its URL, which flows through to the
// finding's `file` (and from there to the report's endpoint) so a reader can
// tell which page leaked it, not just that something did.
export function analyzeSecrets(
  htmlText: string,
  source = "Client-served HTML/JavaScript",
): DiagnosticResult["sastFindings"] {
  const findings: DiagnosticResult["sastFindings"] = [];
  if (!htmlText) return findings;

  SECRET_SIGNATURES.forEach((p) => {
    const m = p.regex.exec(htmlText);
    // Signature match is necessary but not sufficient: skip documented
    // example/placeholder credentials (e.g. AWS's AKIAIOSFODNN7EXAMPLE,
    // sk_live_0000…, YOUR_API_KEY) so they never surface as false positives.
    if (m && !isLikelyPlaceholderSecret(m[0])) {
      findings.push({
        file: source,
        issue: `Exposed Credential Signature (${p.name})`,
        severity: p.severity,
        confidence: p.confidence,
        type: "hardcoded_secrets",
        description: `A string matching the ${p.name} format was detected in the client-served response. ${p.note}`,
        fix: `Remove the credential from client code, rotate it immediately, and proxy any required third-party calls through an authenticated backend that holds the secret server-side.`,
      });
    }
  });
  return findings;
}

// Collects the URLs a page loads code/assets from — the values of every src= and
// href= attribute. Library detection runs over THESE, not the whole document, so
// a version string that merely appears in prose, a changelog, or a code comment
// (e.g. "migrated off jquery-1.9") can't be misread as a loaded dependency. A
// real library is loaded via <script src> / <link href>, so this keeps true
// detections while removing the dominant SCA false positive.
export function extractResourceRefs(htmlText: string): string {
  const refs: string[] = [];
  const re = /(?:src|href)\s*=\s*["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(htmlText)) !== null) refs.push(m[1]);
  return refs.join("\n");
}

// --- SAST: exposed database backup/dump signatures ------------------------------
// Distinctive boilerplate every mainstream dump tool emits verbatim — the kind
// of text that essentially never appears in legitimate prose, unlike a bare
// "CREATE TABLE" (which a blog post *about* SQL could easily contain). A
// world-readable pg_dump/mysqldump file is a common, severe real-world
// exposure (an accidental public backup, a leftover debug endpoint) distinct
// from a credential leak — same signature-match shape as SECRET_SIGNATURES
// above, screened separately so the report names it accurately.
const DATA_DUMP_SIGNATURES = [
  { name: "PostgreSQL Database Dump", regex: /--\s*PostgreSQL database dump/i },
  { name: "PostgreSQL Database Dump", regex: /COPY\s+\S+\s*\([^)]*\)\s*FROM\s+stdin;/i },
  { name: "MySQL Database Dump", regex: /--\s*MySQL dump/i },
  { name: "SQLite Database Dump", regex: /PRAGMA foreign_keys\s*=\s*OFF;/i },
];
export const DATA_DUMP_SIGNATURE_COUNT = DATA_DUMP_SIGNATURES.length;

export function analyzeDataDumpExposure(
  bodyText: string,
  source = "Client-served HTML/JavaScript",
): DiagnosticResult["sastFindings"] {
  const findings: DiagnosticResult["sastFindings"] = [];
  if (!bodyText) return findings;

  for (const sig of DATA_DUMP_SIGNATURES) {
    const m = sig.regex.exec(bodyText);
    if (m) {
      findings.push({
        file: source,
        issue: `Exposed Database Backup (${sig.name})`,
        severity: "critical",
        confidence: "high",
        type: "database_dump_exposure",
        description: `A response matching the format of a ${sig.name} was served from a publicly reachable path. This typically contains complete table contents — every row of every table it covers — for anyone who requests the URL.`,
        fix: "Remove this file from any web-reachable path immediately. Store backups outside the web root (or in access-controlled/private object storage with signed URLs), and rotate any credentials or session tokens the dump exposed.",
      });
      break; // one confirmed signature is enough; further matches are redundant signal
    }
  }
  return findings;
}

// --- SCA: vulnerable-library footprints in markup -----------------------------
// A library is only flagged when its version regex actually matches a known
// vulnerable range in a RESOURCE URL the page loads (src/href), not merely
// anywhere in the served markup. The reported version is the one captured from
// the URL, and advisories are attributed per-library.
// Vulnerable-library footprints. Module-level so LIBRARY_SIGNATURE_COUNT can be
// exported for scan-coverage reporting.
const LIBRARY_SIGNATURES = [
    {
      name: "jQuery",
      match: /jquery[-.](1\.\d+\.\d+|2\.\d+\.\d+)/i,
      severity: "medium" as Severity,
      advisories: ["CVE-2020-11022", "CVE-2020-11023"],
      desc: "jQuery before 3.5.0 is affected by cross-site scripting via htmlPrefilter when passing untrusted HTML to DOM-manipulation methods.",
      fix: "Upgrade jQuery to >= 3.5.0.",
    },
    {
      name: "Bootstrap",
      match: /bootstrap[-./](3\.\d+\.\d+)/i,
      severity: "medium" as Severity,
      advisories: ["CVE-2019-8331"],
      desc: "Bootstrap 3.x is affected by XSS in data-template/tooltip/popover handling and no longer receives security fixes.",
      fix: "Upgrade Bootstrap to >= 4.3.1 (ideally 5.x).",
    },
    {
      name: "AngularJS",
      match: /angular[-.](1\.[0-8]\.\d+)/i,
      severity: "low" as Severity,
      advisories: ["EOL"],
      desc: "AngularJS (1.x) is past end-of-life and receives no further security patches.",
      fix: "Migrate off AngularJS to a maintained framework.",
    },
    {
      name: "Lodash",
      // Vulnerable range is lodash < 4.17.21 (the fix floor for the CVEs below).
      // Matches 4.0.0–4.16.x (any patch) and 4.17.0–4.17.20, but NOT 4.17.21+.
      // The previous pattern stopped at 4.16.x, missing the entire — and most
      // common — vulnerable 4.17.0–4.17.20 line.
      match: /lodash[@/-](4\.(?:[0-9]|1[0-6])\.\d+|4\.17\.(?:20|1[0-9]|[0-9]))\b/i,
      severity: "high" as Severity,
      advisories: ["CVE-2019-10744", "CVE-2020-8203", "CVE-2021-23337"],
      desc: "lodash before 4.17.21 is affected by prototype pollution (CVE-2019-10744 in defaultsDeep, CVE-2020-8203 in zipObjectDeep/set) and command injection via template (CVE-2021-23337).",
      fix: "Upgrade lodash to >= 4.17.21.",
    },
  ];
export const LIBRARY_SIGNATURE_COUNT = LIBRARY_SIGNATURES.length;

export function analyzeLibraries(htmlText: string): DiagnosticResult["scaLibraries"] {
  const libs: DiagnosticResult["scaLibraries"] = [];
  if (!htmlText) return libs;
  const refs = extractResourceRefs(htmlText);
  if (!refs) return libs;

  LIBRARY_SIGNATURES.forEach((lib) => {
    const m = lib.match.exec(refs);
    if (m) {
      libs.push({
        name: lib.name,
        version: m[1],
        status: "vuln",
        advisories: lib.advisories,
        severity: lib.severity,
        description: lib.desc,
        fix: lib.fix,
      });
    }
  });
  return libs;
}
