// Row → domain-object mappers. SQLite stores JSON columns as text and booleans
// as 0/1; these normalize a raw row into the typed shapes the app uses.
import { User, Scan, ApiKey, DomainVerification } from '../../src/types.js';

export function rowToUser(row: any): User | undefined {
  if (!row) return undefined;
  return {
    id: row.id, email: row.email, credits: row.credits,
    notifyWebhook: row.notifyWebhook ?? undefined, createdAt: row.createdAt,
  };
}

export function rowToScan(row: any): Scan | undefined {
  if (!row) return undefined;
  return {
    id: row.id,
    userId: row.userId,
    url: row.url,
    authHeader: row.authHeader ?? undefined,
    status: row.status,
    score: row.score ?? undefined,
    severity: row.severity ?? undefined,
    findings: row.findings ? JSON.parse(row.findings) : undefined,
    aiSummary: row.aiSummary ?? undefined,
    aiReasoning: row.aiReasoning ?? undefined,
    narrationLog: row.narrationLog ? JSON.parse(row.narrationLog) : undefined,
    executiveBreakdown: row.executiveBreakdown ? JSON.parse(row.executiveBreakdown) : undefined,
    evidence: row.evidence ? JSON.parse(row.evidence) : undefined,
    error: row.error ?? undefined,
    createdAt: row.createdAt,
    completedAt: row.completedAt ?? undefined,
  };
}

export function rowToApiKey(row: any): ApiKey {
  return {
    id: row.id, userId: row.userId, keyPreview: row.keyPreview,
    credits: row.credits, active: !!row.active, createdAt: row.createdAt,
  };
}

export function rowToDomainVerification(row: any): DomainVerification | undefined {
  if (!row) return undefined;
  return {
    id: row.id, userId: row.userId, domain: row.domain, token: row.token,
    verified: !!row.verified, createdAt: row.createdAt, verifiedAt: row.verifiedAt ?? undefined,
    method: row.method ?? undefined, attestation: row.attestation ?? undefined,
  };
}
