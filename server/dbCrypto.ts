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
