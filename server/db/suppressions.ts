// Suppression rules (false-positive management). Applied as a read-model (see
// readModel.getScanWithSuppressedFindings), so add/remove is a simple row
// mutation with no scan rewrites.
import type Database from 'better-sqlite3';
import crypto from 'crypto';
import { SuppressionRule } from '../../src/types.js';

export function makeSuppressionsRepo(db: Database.Database) {
  const listSuppressions = (userId: string): SuppressionRule[] =>
    db.prepare('SELECT * FROM suppressions WHERE userId = ?').all(userId) as SuppressionRule[];

  const addSuppression = (userId: string, targetUrl: string, findingTitle: string, reason: string): SuppressionRule => {
    const id = 'supp_' + crypto.randomBytes(8).toString('hex');
    const rule: SuppressionRule = { id, userId, targetUrl, findingTitle, reason, createdAt: new Date().toISOString() };
    db.prepare('INSERT INTO suppressions (id, userId, targetUrl, findingTitle, reason, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
      .run(id, userId, targetUrl, findingTitle, reason, rule.createdAt);
    return rule;
  };

  const removeSuppression = (userId: string, ruleId: string): boolean =>
    db.prepare('DELETE FROM suppressions WHERE id = ? AND userId = ?').run(ruleId, userId).changes > 0;

  return { listSuppressions, addSuppression, removeSuppression };
}

export type SuppressionsRepo = ReturnType<typeof makeSuppressionsRepo>;
