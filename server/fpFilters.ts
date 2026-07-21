// False-positive filters for signature-confirmed findings. Seclayer's core
// promise is low false positives, so a signature match alone isn't always enough
// to ship a finding — two detectors need a second gate:
//
//  1. Secret signatures match documented example / placeholder credentials that
//     are not real leaks (Amazon's own `AKIAIOSFODNN7EXAMPLE`, `sk_live_xxxx…`,
//     `YOUR_API_KEY`, all-zero filler). Reporting those erodes trust fast.
//  2. A reflected-XSS payload echoed into a NON-HTML response (a JSON API) or
//     into a non-executing HTML context (an HTML comment, <textarea>, <title>)
//     is reflected but not executable — reporting it as XSS is a false positive.
//
// These are pure functions so they can be unit-tested without a live scan.

// --- Secret placeholder detection -------------------------------------------

// Documentation / sample tokens and filler words that appear in READMEs, SDK
// snippets and config templates — never in a real leaked credential.
const PLACEHOLDER_MARKERS = [
  "example", "placeholder", "your_", "your-", "yourkey", "yourapikey",
  "dummy", "sample", "redacted", "changeme", "change_me", "todo",
  "xxxx", "test_key", "testkey", "notreal", "fake", "insertkey",
];

// Amazon's canonical documentation access-key id — present in countless tutorials.
const KNOWN_EXAMPLE_TOKENS = new Set(["AKIAIOSFODNN7EXAMPLE"]);

const KNOWN_PREFIXES = ["sk_live_", "sk_test_", "gho_", "ghp_", "AKIA", "AIzaSy"];

function stripKnownPrefix(token: string): string {
  for (const p of KNOWN_PREFIXES) {
    if (token.startsWith(p)) return token.slice(p.length);
  }
  return token;
}

// Shannon entropy in bits/char — low for repetitive filler ("000000", "aaaa"),
// high for a real random key.
function shannonEntropy(s: string): number {
  if (!s) return 0;
  const counts: Record<string, number> = {};
  for (const ch of s) counts[ch] = (counts[ch] || 0) + 1;
  let bits = 0;
  for (const ch in counts) {
    const p = counts[ch] / s.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

// A run of >= `len` consecutive ascending characters, e.g. "0123456789" or
// "abcdefgh" — the shape of a hand-typed filler value, not a random key.
function hasMonotonicRun(s: string, len = 6): boolean {
  let run = 1;
  for (let i = 1; i < s.length; i++) {
    if (s.charCodeAt(i) === s.charCodeAt(i - 1) + 1) {
      if (++run >= len) return true;
    } else {
      run = 1;
    }
  }
  return false;
}

// True when a matched secret is almost certainly an example/placeholder rather
// than a real leaked credential, and should NOT be reported as a finding.
export function isLikelyPlaceholderSecret(token: string): boolean {
  if (!token) return false;
  if (KNOWN_EXAMPLE_TOKENS.has(token)) return true;

  const lower = token.toLowerCase();
  if (PLACEHOLDER_MARKERS.some((m) => lower.includes(m))) return true;

  const variable = stripKnownPrefix(token);
  if (variable.length >= 8) {
    // A single character repeated for the whole body (e.g. sk_live_00000000…).
    if (/^(.)\1+$/.test(variable)) return true;
    if (shannonEntropy(variable) < 2.5) return true;
    if (hasMonotonicRun(variable)) return true;
  }
  return false;
}

// --- Reflected-XSS execution gate -------------------------------------------

// Content types whose bodies a browser will not parse as HTML, so a reflected
// `<script>` in them is inert — not XSS.
const NON_HTML_CONTENT_TYPES = [
  "application/json", "text/plain", "text/csv", "application/xml", "text/xml",
  "application/javascript", "text/javascript", "application/octet-stream",
  "text/css", "application/pdf",
];

// HTML contexts whose content model is (escapable) raw text: a literal
// `<script>` inside them is treated as text and never executed.
const NEUTRALIZING_CONTEXTS: Array<{ open: RegExp; close: RegExp }> = [
  { open: /<!--/g, close: /-->/g },
  { open: /<title[\s>]/gi, close: /<\/title/gi },
  { open: /<textarea[\s>]/gi, close: /<\/textarea/gi },
  { open: /<noscript[\s>]/gi, close: /<\/noscript/gi },
  { open: /<xmp[\s>]/gi, close: /<\/xmp/gi },
  { open: /<style[\s>]/gi, close: /<\/style/gi },
];

// Index of the last regex match strictly before `before`, or -1.
function lastIndexBefore(html: string, re: RegExp, before: number): number {
  re.lastIndex = 0;
  let last = -1;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    if (m.index >= before) break;
    last = m.index;
    if (m.index === re.lastIndex) re.lastIndex++; // guard against zero-width loops
  }
  return last;
}

// True when a reflected marker at `markerIndex` sits inside a non-executing
// context (an open tag with no matching close between it and the marker).
function inNeutralizingContext(html: string, markerIndex: number): boolean {
  return NEUTRALIZING_CONTEXTS.some(({ open, close }) => {
    const lastOpen = lastIndexBefore(html, open, markerIndex);
    if (lastOpen === -1) return false;
    const lastClose = lastIndexBefore(html, close, markerIndex);
    return lastOpen > lastClose; // opened and not yet closed → marker is enclosed
  });
}

// A reflected XSS marker is only exploitable when the response is HTML the
// browser will parse AND the marker lands in an executing context. Returns false
// (→ suppress the finding) for JSON/plain/etc. responses and for reflections
// buried in comments / <textarea> / <title> and similar raw-text elements.
export function xssReflectionExecutes(
  contentType: string | null | undefined,
  html: string,
  markerIndex: number,
): boolean {
  if (markerIndex < 0) return false;
  const ct = (contentType || "").toLowerCase();
  // Only reject content types explicitly known to be non-HTML; an absent or
  // unrecognized type is treated as possibly-HTML to avoid false negatives.
  if (NON_HTML_CONTENT_TYPES.some((t) => ct.includes(t))) return false;
  if (inNeutralizingContext(html, markerIndex)) return false;
  return true;
}
