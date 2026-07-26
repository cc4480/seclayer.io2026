// Domain-ownership verification. Gates the scanner's active exploit probes:
// only a verified domain (DNS/file proof or an explicit attestation) unlocks
// them (see server/domainVerify.ts + scanner's allowActiveProbes).
import type Database from 'better-sqlite3';
import crypto from 'crypto';
import { DomainVerification } from '../../src/types.js';
import { rowToDomainVerification } from './mappers.js';

export function makeDomainsRepo(db: Database.Database) {
  const listDomainVerifications = (userId: string): DomainVerification[] =>
    (db.prepare('SELECT * FROM domain_verifications WHERE userId = ? ORDER BY createdAt DESC').all(userId) as any[])
      .map((r) => rowToDomainVerification(r)!);

  const getDomainVerification = (userId: string, domain: string): DomainVerification | undefined =>
    rowToDomainVerification(
      db.prepare('SELECT * FROM domain_verifications WHERE userId = ? AND domain = ?').get(userId, domain),
    );

  // Creates a pending verification (or returns the existing one) so repeated
  // "start" calls hand back the same token/instructions.
  const startDomainVerification = (userId: string, domain: string, token: string): DomainVerification => {
    const existing = getDomainVerification(userId, domain);
    if (existing) return existing;
    const id = 'dv_' + crypto.randomBytes(8).toString('hex');
    db.prepare('INSERT INTO domain_verifications (id, userId, domain, token, verified, createdAt) VALUES (?, ?, ?, ?, 0, ?)')
      .run(id, userId, domain, token, new Date().toISOString());
    return getDomainVerification(userId, domain)!;
  };

  const markDomainVerified = (userId: string, domain: string, method: 'dns' | 'file' = 'dns'): void => {
    db.prepare('UPDATE domain_verifications SET verified = 1, verifiedAt = ?, method = ? WHERE userId = ? AND domain = ?')
      .run(new Date().toISOString(), method, userId, domain);
  };

  // Records an explicit ownership/authorization ATTESTATION and marks the domain
  // verified. The exact statement agreed to is stored for the audit trail.
  // Upserts so a domain with no prior pending record can be attested in one step.
  const attestDomainOwnership = (userId: string, domain: string, attestation: string): DomainVerification => {
    const now = new Date().toISOString();
    const existing = getDomainVerification(userId, domain);
    if (!existing) {
      const id = 'dv_' + crypto.randomBytes(8).toString('hex');
      const token = crypto.randomBytes(16).toString('hex');
      db.prepare(
        'INSERT INTO domain_verifications (id, userId, domain, token, verified, createdAt, verifiedAt, method, attestation) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)'
      ).run(id, userId, domain, token, now, now, 'attestation', attestation);
    } else {
      db.prepare(
        'UPDATE domain_verifications SET verified = 1, verifiedAt = ?, method = ?, attestation = ? WHERE userId = ? AND domain = ?'
      ).run(now, 'attestation', attestation, userId, domain);
    }
    return getDomainVerification(userId, domain)!;
  };

  const isDomainVerified = (userId: string, domain: string): boolean =>
    !!getDomainVerification(userId, domain)?.verified;

  return {
    listDomainVerifications, getDomainVerification, startDomainVerification,
    markDomainVerified, attestDomainOwnership, isDomainVerified,
  };
}
