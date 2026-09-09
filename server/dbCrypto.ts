// Small, pure crypto/formatting helpers shared by the database layer and its
// schema migration. Kept in their own module so both db.ts and dbSchema.ts can
// use them without a circular import.
import crypto from "crypto";

// Tokens (magic-link, session, API keys) are random secrets; only their
// SHA-256 hash is persisted so a DB read cannot reveal a usable value.
export function hashToken(raw: string): string {
  return crypto.createHash("sha256").update(raw).digest("hex");
}

// A safe-to-display fragment of a secret (prefix + last 4 chars). Never
// reversible back to the real value; used only for listing existing keys.
export function maskKey(raw: string): string {
  return raw.length <= 16 ? raw : `${raw.slice(0, 12)}…${raw.slice(-4)}`;
}

// Legacy plaintext API keys were stored as "sl_live_<32 hex>". Used by the
// one-time migration that rewrites them to their hash + preview.
export const LEGACY_RAW_KEY_PATTERN = /^sl_live_[0-9a-f]{32}$/;

// --- Encryption at rest for user-supplied third-party secrets ---------------
//
// Everything else in this module hashes or masks, because everything else is a
// secret WE issued and can afford to verify rather than recover. A user's own
// DeepSeek key is different: the scan pipeline has to send the real value to
// DeepSeek, so it has to be recoverable, so hashing is not an option and it was
// simply stored in cleartext. That put a billable third-party credential in
// every database dump, backup and copy of data.sqlite.
//
// AES-256-GCM under ENCRYPTION_KEY (32 bytes, base64). Format is
// "enc.v1.<iv>.<tag>.<ciphertext>", each part base64 — the version prefix is
// what lets openSecret() tell a sealed value from a legacy plaintext one, so
// existing rows keep working and are upgraded in place the next time the user
// saves. GCM is authenticated, so a tampered row fails loudly rather than
// decrypting to garbage that then gets sent to a third party.

const SEAL_PREFIX = "enc.v1.";

export function isEncryptionConfigured(): boolean {
  return Boolean(process.env.ENCRYPTION_KEY);
}

function sealingKey(): Buffer {
  const raw = process.env.ENCRYPTION_KEY;
  if (!raw) throw new Error("ENCRYPTION_KEY is not set — cannot seal or open secrets");
  const key = Buffer.from(raw, "base64");
  if (key.length !== 32) {
    throw new Error(
      'ENCRYPTION_KEY must decode to exactly 32 bytes — generate one with: ' +
        `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`,
    );
  }
  return key;
}

// Throws when no key is configured. Callers must decide what that means for
// them rather than silently falling back to plaintext, which is the failure
// mode this function exists to remove.
export function sealSecret(raw: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", sealingKey(), iv);
  const ct = Buffer.concat([cipher.update(raw, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${SEAL_PREFIX}${iv.toString("base64")}.${tag.toString("base64")}.${ct.toString("base64")}`;
}

export function isSealed(stored: string): boolean {
  return stored.startsWith(SEAL_PREFIX);
}

// Legacy plaintext passes through unchanged so rows written before sealing
// existed keep working. Returns null when a sealed value cannot be opened —
// wrong key, corrupted row, key rotated — because handing a caller a wrong
// secret to spend against a paid API is worse than telling it there is none.
export function openSecret(stored: string | null): string | null {
  if (!stored) return null;
  if (!isSealed(stored)) return stored;
  try {
    const [ivB64, tagB64, ctB64] = stored.slice(SEAL_PREFIX.length).split(".");
    if (!ivB64 || !tagB64 || !ctB64) return null;
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      sealingKey(),
      Buffer.from(ivB64, "base64"),
    );
    decipher.setAuthTag(Buffer.from(tagB64, "base64"));
    return Buffer.concat([
      decipher.update(Buffer.from(ctB64, "base64")),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    return null;
  }
}
