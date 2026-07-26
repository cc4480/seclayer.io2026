// API keys domain. Keys are stored as a SHA-256 hash + masked preview only; the
// raw value is returned exactly once, at creation. Depends on the accounts repo
// for balance reads/deductions.
import type Database from 'better-sqlite3';
import crypto from 'crypto';
import { ApiKey, User } from '../../src/types.js';
import { hashToken, maskKey } from './util.js';
import { rowToApiKey } from './mappers.js';
import type { AccountsRepo } from './accounts.js';

export function makeApiKeysRepo(db: Database.Database, accounts: AccountsRepo) {
  const listApiKeys = (userId: string): ApiKey[] =>
    (db.prepare('SELECT * FROM api_keys WHERE userId = ?').all(userId) as any[]).map((r) => rowToApiKey(r));

  // Returns the new key row (safe to persist/display forever) alongside the raw
  // secret (safe to show exactly once, in the HTTP response to this call).
  const generateApiKey = (userId: string): { apiKey: ApiKey; rawKey: string } => {
    const user = accounts.getUser(userId);
    if (!user) throw new Error('User not found');
    const id = 'key_' + crypto.randomBytes(8).toString('hex');
    const rawKey = 'sl_live_' + crypto.randomBytes(16).toString('hex');
    db.prepare('INSERT INTO api_keys (id, userId, key, keyPreview, credits, active, createdAt) VALUES (?, ?, ?, ?, ?, 1, ?)')
      .run(id, userId, hashToken(rawKey), maskKey(rawKey), user.credits, new Date().toISOString());
    const apiKey = rowToApiKey(db.prepare('SELECT * FROM api_keys WHERE id = ?').get(id));
    return { apiKey, rawKey };
  };

  const revokeApiKey = (userId: string, keyId: string): boolean =>
    db.prepare('UPDATE api_keys SET active = 0 WHERE id = ? AND userId = ?').run(keyId, userId).changes > 0;

  const validateApiKeyAndDeduct = (apiKeyString: string, quantity: number = 1): User | null => {
    const keyRow: any = db.prepare('SELECT * FROM api_keys WHERE key = ?').get(hashToken(apiKeyString));
    if (!keyRow || !keyRow.active) return null;
    const user = accounts.getUser(keyRow.userId);
    if (!user || user.credits < quantity) return null;
    return accounts.addCredits(user.id, -quantity, 'scan_debit');
  };

  return { listApiKeys, generateApiKey, revokeApiKey, validateApiKeyAndDeduct };
}
