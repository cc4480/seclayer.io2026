import crypto from 'crypto';

// URL normalization used by suppression matching (strip scheme, trailing
// slashes, case) so a rule keyed on one URL form matches a scan on another.
export function cleanUrl(urlStr: string): string {
  try {
    return urlStr.replace(/https?:\/\//i, '').replace(/\/+$/, '').trim().toLowerCase();
  } catch {
    return String(urlStr || '').trim().toLowerCase();
  }
}

// Secrets (sessions, magic links, API keys) are stored as their SHA-256 hash
// only — a DB read alone can never yield a usable token.
export function hashToken(raw: string): string {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

// A safe-to-display fragment of a secret (prefix + last 4 chars). Never
// reversible back to the real value; used only for listing existing keys.
export function maskKey(raw: string): string {
  return raw.length <= 16 ? raw : `${raw.slice(0, 12)}…${raw.slice(-4)}`;
}
