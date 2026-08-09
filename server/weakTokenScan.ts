// Scans JSON API response bodies for security-sensitive tokens (password-reset
// tokens, OTPs, verification/passcodes) that are observably too short/
// low-entropy to resist brute-forcing — e.g. a token minted with
// Math.random().toString(36) instead of a CSPRNG. Purely observational: unlike
// server/redTeam/weakSessionToken.ts (which must REPRODUCE an opaque hash to
// prove weakness), this only measures a value the app already put in its own
// response — the JSON-response analogue of analyzeSecrets' markup scan in
// server/staticAnalysis.ts.
import type { DiagnosticResult } from "./scanTypes.js";

// Key names specific enough to signal "this is a security-sensitive token" —
// deliberately NOT "id"/"code" alone, so an 8-character orderId/productId
// never trips this. A field merely containing one of these substrings
// (resetToken, sessionToken, otp, verificationCode, ...) qualifies.
const TOKEN_KEY_PATTERN = /token|otp|passcode|verificationcode|resetcode/i;

// Below MIN_LEN we'd be flagging things like 4-6 digit SMS/2FA OTP codes,
// whose security model relies on rate-limiting (which is out of scope for a
// black-box length/charset check) rather than raw entropy — deliberately not
// this probe's concern, to keep false positives low on legitimate apps.
const MIN_LEN = 8;
const MAX_LEN = 24; // real CSPRNG tokens (hex/base64, JWTs) are longer than this
const ENTROPY_BITS_THRESHOLD = 64; // a widely-used floor below which a token is realistically brute-forceable

function estimateEntropyBits(value: string): number {
  let charsetSize = 0;
  if (/[a-z]/.test(value)) charsetSize += 26;
  if (/[A-Z]/.test(value)) charsetSize += 26;
  if (/[0-9]/.test(value)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(value)) charsetSize += 32; // rough allowance for punctuation/symbols
  if (charsetSize < 2) return 0;
  return value.length * Math.log2(charsetSize);
}

function isWeakTokenValue(value: string): boolean {
  if (value.length < MIN_LEN || value.length > MAX_LEN) return false;
  if (!/^[\x21-\x7e]+$/.test(value)) return false; // printable ASCII only — don't misread opaque binary/unicode blobs
  return estimateEntropyBits(value) < ENTROPY_BITS_THRESHOLD;
}

// Recursively walk a parsed JSON value for token-named string leaves. Bounded
// depth and hit count as a backstop against a pathological document — JSON.parse
// output is already acyclic, so this is just a safety margin, not cycle guarding.
function walk(node: unknown, keyPath: string, out: Array<{ key: string; value: string }>, depth: number): void {
  if (depth > 6 || out.length >= 5 || !node || typeof node !== "object") return;
  for (const [key, val] of Object.entries(node as Record<string, unknown>)) {
    const path = keyPath ? `${keyPath}.${key}` : key;
    if (typeof val === "string" && TOKEN_KEY_PATTERN.test(key) && isWeakTokenValue(val)) {
      out.push({ key: path, value: val });
    } else if (val && typeof val === "object") {
      walk(val, path, out, depth + 1);
    }
  }
}

export function weakTokenFindings(bodyText: string, source: string): DiagnosticResult["sastFindings"] {
  const findings: DiagnosticResult["sastFindings"] = [];
  if (!bodyText || bodyText.length > 300_000) return findings;
  const trimmed = bodyText.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return findings;

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return findings;
  }

  const hits: Array<{ key: string; value: string }> = [];
  walk(parsed, "", hits, 0);

  for (const hit of hits) {
    const bits = Math.round(estimateEntropyBits(hit.value));
    findings.push({
      file: source,
      issue: `Weak/Predictable Security Token (${hit.key})`,
      severity: "high",
      confidence: "medium",
      type: "weak_token_entropy",
      description: `The response field "${hit.key}" returned a security token ("${hit.value}") with only ~${bits} bits of estimated entropy (${hit.value.length} characters). A token this short/predictable can realistically be brute-forced, letting an attacker guess valid tokens issued to other users.`,
      fix: "Generate security tokens with a cryptographically secure random source (e.g. crypto.randomBytes(32).toString('hex') in Node.js) producing at least 128 bits of entropy — never Math.random() or another non-CSPRNG source.",
    });
  }
  return findings;
}
