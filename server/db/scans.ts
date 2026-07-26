// Scans domain: scan lifecycle rows plus the out-of-band collaborator tables
// (blind SSRF/RCE callback proof).
import type Database from 'better-sqlite3';
import crypto from 'crypto';
import { Scan, OobEvent } from '../../src/types.js';
import { rowToScan } from './mappers.js';

export function makeScansRepo(db: Database.Database) {
  const listScans = (userId: string): Scan[] => {
    const rows = db.prepare('SELECT * FROM scans WHERE userId = ? ORDER BY createdAt DESC').all(userId);
    return rows.map((r) => rowToScan(r)!).filter(Boolean);
  };

  const getScan = (id: string): Scan | undefined =>
    rowToScan(db.prepare('SELECT * FROM scans WHERE id = ?').get(id));

  // The most recent *completed* scan of the same target for this user, other
  // than `excludeScanId` — the baseline for monitoring regression detection.
  const getPreviousCompletedScan = (userId: string, url: string, excludeScanId: string): Scan | undefined =>
    rowToScan(db.prepare(
      "SELECT * FROM scans WHERE userId = ? AND url = ? AND status = 'complete' AND id != ? ORDER BY createdAt DESC LIMIT 1"
    ).get(userId, url, excludeScanId));

  const createScan = (userId: string, url: string, authHeader?: string): Scan => {
    const id = 'scan_' + crypto.randomBytes(8).toString('hex');
    const now = new Date().toISOString();
    db.prepare('INSERT INTO scans (id, userId, url, authHeader, status, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
      .run(id, userId, url, authHeader ?? null, 'queued', now);
    return getScan(id)!;
  };

  const updateScan = (id: string, updates: Partial<Scan>): Scan => {
    const existing = getScan(id);
    if (!existing) throw new Error('Scan not found');
    const merged = { ...existing, ...updates };
    db.prepare(`
      UPDATE scans SET status = ?, score = ?, severity = ?, findings = ?, aiSummary = ?, aiReasoning = ?, narrationLog = ?, executiveBreakdown = ?, evidence = ?, error = ?, completedAt = ?
      WHERE id = ?
    `).run(
      merged.status,
      merged.score ?? null,
      merged.severity ?? null,
      merged.findings ? JSON.stringify(merged.findings) : null,
      merged.aiSummary ?? null,
      merged.aiReasoning ?? null,
      merged.narrationLog ? JSON.stringify(merged.narrationLog) : null,
      merged.executiveBreakdown ? JSON.stringify(merged.executiveBreakdown) : null,
      merged.evidence ? JSON.stringify(merged.evidence) : null,
      merged.error ?? null,
      merged.completedAt ?? null,
      id,
    );
    return getScan(id)!;
  };

  // A token is registered when the scanner mints a callback URL, so the public
  // /api/oob/:token endpoint only records hits for tokens WE issued.
  const registerOobToken = (token: string, scanId?: string): void => {
    db.prepare('INSERT OR IGNORE INTO oob_tokens (token, scanId, createdAt) VALUES (?, ?, ?)')
      .run(token, scanId ?? null, new Date().toISOString());
  };

  // Records a callback IFF the token was issued by us within the last 15 minutes.
  // Opportunistically prunes rows older than a day. Unknown/expired tokens are a
  // no-op (the route still returns 200 so it leaks nothing about validity).
  const recordOobEvent = (
    token: string,
    ev: { method: string; sourceIp: string; path: string; userAgent?: string },
  ): boolean => {
    const tok = db.prepare('SELECT createdAt FROM oob_tokens WHERE token = ?').get(token) as
      | { createdAt: string } | undefined;
    if (!tok) return false;
    if (Date.now() - new Date(tok.createdAt).getTime() > 15 * 60 * 1000) return false;
    const id = 'oob_' + crypto.randomBytes(8).toString('hex');
    db.prepare(
      'INSERT INTO oob_events (id, token, method, sourceIp, path, userAgent, receivedAt) VALUES (?, ?, ?, ?, ?, ?, ?)',
    ).run(id, token, ev.method, ev.sourceIp, ev.path, ev.userAgent ?? null, new Date().toISOString());
    const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    db.prepare('DELETE FROM oob_events WHERE receivedAt < ?').run(cutoff);
    db.prepare('DELETE FROM oob_tokens WHERE createdAt < ?').run(cutoff);
    return true;
  };

  const getOobEvents = (token: string): OobEvent[] =>
    db.prepare('SELECT * FROM oob_events WHERE token = ? ORDER BY receivedAt ASC').all(token) as OobEvent[];

  return {
    listScans, getScan, getPreviousCompletedScan, createScan, updateScan,
    registerOobToken, recordOobEvent, getOobEvents,
  };
}
