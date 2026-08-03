// Row → domain-object mappers for the database layer. These are pure functions
// of a raw SQLite row (they never touch the connection), extracted from db.ts so
// the persistence class holds queries + business logic, not field plumbing.
import type { User, Scan, ApiKey, DomainVerification, MonitoredTarget, NmapScan } from "../src/types.js";

export function rowToUser(row: any): User | undefined {
  if (!row) return undefined;
  return {
    id: row.id, email: row.email, credits: row.credits,
    notifyWebhook: row.notifyWebhook ?? undefined, createdAt: row.createdAt,
    emailDigest: row.emailDigest ? true : false,
    lastDigestAt: row.lastDigestAt ?? undefined,
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
    shareToken: row.shareToken ?? undefined,
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
    method: row.method ?? undefined,
  };
}

export function rowToNmapScan(row: any): NmapScan | undefined {
  if (!row) return undefined;
  return {
    id: row.id,
    userId: row.userId,
    url: row.url,
    resolvedIp: row.resolvedIp ?? undefined,
    status: row.status,
    nmapVersion: row.nmapVersion ?? undefined,
    result: row.result ? JSON.parse(row.result) : undefined,
    rawXml: row.rawXml ?? undefined,
    error: row.error ?? undefined,
    createdAt: row.createdAt,
    startedAt: row.startedAt ?? undefined,
    completedAt: row.completedAt ?? undefined,
  };
}

export function rowToMonitoredTarget(row: any): MonitoredTarget {
  return {
    id: row.id,
    userId: row.userId,
    url: row.url,
    frequencyDays: row.frequencyDays,
    scheduleString: row.scheduleString ?? undefined,
    scanHour: row.scanHour ?? null,
    scanMinute: row.scanMinute ?? null,
    scanWeekday: row.scanWeekday ?? null,
    lastScannedAt: row.lastScannedAt ?? undefined,
    nextScanAt: row.nextScanAt ?? undefined,
    createdAt: row.createdAt,
    lastError: row.lastError ?? undefined,
    // Stored as 0/1 in SQLite; surfaced as a real boolean.
    paused: !!row.paused,
  };
}
