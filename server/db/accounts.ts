// Accounts domain: users, credit balance + transaction ledger, magic-link login
// tokens, and sessions. Tokens are stored hashed only.
import type Database from 'better-sqlite3';
import crypto from 'crypto';
import { User, CreditTransaction } from '../../src/types.js';
import { hashToken } from './util.js';
import { rowToUser } from './mappers.js';

export function makeAccountsRepo(db: Database.Database) {
  const getUser = (id: string): User | undefined =>
    rowToUser(db.prepare('SELECT * FROM users WHERE id = ?').get(id));

  const getUserByEmail = (email: string): User | undefined =>
    rowToUser(db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim()));

  const getOrCreateUser = (email: string): User => {
    const normEmail = email.toLowerCase().trim();
    const existing = getUserByEmail(normEmail);
    if (existing) return existing;

    const id = 'user_' + crypto.randomBytes(6).toString('hex');
    const now = new Date().toISOString();
    // No API key is provisioned here: a key's raw value is only ever shown once,
    // at generateApiKey() time, so a key created at signup could never be shown.
    const tx = db.transaction(() => {
      db.prepare('INSERT INTO users (id, email, credits, createdAt) VALUES (?, ?, ?, ?)')
        .run(id, normEmail, 5, now); // 5 signup credits
      db.prepare('INSERT INTO transactions (id, userId, amount, type, createdAt) VALUES (?, ?, ?, ?, ?)')
        .run('tx-signup-' + id, id, 5, 'purchase', now);
    });
    tx();
    return getUser(id)!;
  };

  const setUserWebhook = (userId: string, url: string | null): User | undefined => {
    db.prepare("UPDATE users SET notifyWebhook = ? WHERE id = ?").run(url, userId);
    return getUser(userId);
  };

  const addCredits = (userId: string, amount: number, type: 'purchase' | 'scan_debit', stripeSessionId?: string): User => {
    const user = getUser(userId);
    if (!user) throw new Error('User not found');
    const newCredits = Math.max(0, user.credits + amount);
    const tx = db.transaction(() => {
      db.prepare('UPDATE users SET credits = ? WHERE id = ?').run(newCredits, userId);
      db.prepare('UPDATE api_keys SET credits = ? WHERE userId = ? AND active = 1').run(newCredits, userId);
      db.prepare('INSERT INTO transactions (id, userId, amount, type, stripeSessionId, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
        .run('tx_' + crypto.randomBytes(8).toString('hex'), userId, amount, type, stripeSessionId ?? null, new Date().toISOString());
    });
    tx();
    return getUser(userId)!;
  };

  const deductCredits = (userId: string, amount: number): boolean => {
    const user = getUser(userId);
    if (!user || user.credits < amount) return false;
    addCredits(userId, -amount, 'scan_debit');
    return true;
  };

  const listTransactions = (userId: string): CreditTransaction[] =>
    db.prepare('SELECT * FROM transactions WHERE userId = ? ORDER BY createdAt DESC').all(userId) as CreditTransaction[];

  // Idempotency guard for Stripe webhooks: true if a purchase for this Checkout
  // session was already recorded, so retries never grant duplicate credits.
  const hasTransactionForSession = (sessionId: string): boolean =>
    !!db.prepare('SELECT 1 FROM transactions WHERE stripeSessionId = ? LIMIT 1').get(sessionId);

  // --- Magic-link auth + sessions ---
  const createLoginToken = (email: string, ttlMs = 15 * 60 * 1000): string => {
    const raw = crypto.randomBytes(32).toString('hex');
    const now = Date.now();
    db.prepare('INSERT INTO login_tokens (tokenHash, email, expiresAt, createdAt) VALUES (?, ?, ?, ?)')
      .run(hashToken(raw), email.toLowerCase().trim(), new Date(now + ttlMs).toISOString(), new Date(now).toISOString());
    return raw;
  };

  const consumeLoginToken = (raw: string): string | null => {
    const hash = hashToken(raw);
    const row: any = db.prepare('SELECT * FROM login_tokens WHERE tokenHash = ?').get(hash);
    if (!row || row.consumedAt) return null;
    if (new Date(row.expiresAt).getTime() < Date.now()) return null;
    db.prepare('UPDATE login_tokens SET consumedAt = ? WHERE tokenHash = ?').run(new Date().toISOString(), hash);
    return row.email;
  };

  const createSession = (userId: string, ttlMs = 30 * 24 * 60 * 60 * 1000): string => {
    const raw = crypto.randomBytes(32).toString('hex');
    const now = Date.now();
    db.prepare('INSERT INTO sessions (tokenHash, userId, expiresAt, createdAt) VALUES (?, ?, ?, ?)')
      .run(hashToken(raw), userId, new Date(now + ttlMs).toISOString(), new Date(now).toISOString());
    return raw;
  };

  const getSessionUserId = (raw: string): string | null => {
    const row: any = db.prepare('SELECT * FROM sessions WHERE tokenHash = ?').get(hashToken(raw));
    if (!row) return null;
    if (new Date(row.expiresAt).getTime() < Date.now()) {
      db.prepare('DELETE FROM sessions WHERE tokenHash = ?').run(row.tokenHash);
      return null;
    }
    return row.userId;
  };

  const deleteSession = (raw: string): void => {
    db.prepare('DELETE FROM sessions WHERE tokenHash = ?').run(hashToken(raw));
  };

  return {
    getUser, getUserByEmail, getOrCreateUser, setUserWebhook, addCredits, deductCredits,
    listTransactions, hasTransactionForSession,
    createLoginToken, consumeLoginToken, createSession, getSessionUserId, deleteSession,
  };
}

export type AccountsRepo = ReturnType<typeof makeAccountsRepo>;
