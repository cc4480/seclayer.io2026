// Postgres folds UNQUOTED identifiers to lower case, so `SELECT *` returns rows
// keyed `createdat`/`userid`/`aisummary` — while the row mappers in
// server/dbMappers.ts read camelCase (`row.createdAt`, `row.userId`, …). Left
// unhandled, every camelCase field would silently read `undefined`.
//
// Rather than quote every identifier in every query (fragile) or fork the
// mappers per backend, the Postgres adapter runs each row through normalizeRow
// BEFORE the mappers. SQLite is unaffected (it preserves the declared case), so
// the mappers stay identical for both backends.
//
// The authoritative list of camelCase columns (every column in
// server/pg/schema.sql that has an uppercase letter). Keep in sync with the
// schema; the test asserts each maps to a distinct lower-cased key.
const CAMEL_COLUMNS = [
  "createdAt", "notifyWebhook", "deepseekApiKey", "emailDigest", "lastDigestAt",
  "userId", "authHeader", "aiSummary", "completedAt", "aiReasoning",
  "narrationLog", "executiveBreakdown", "shareToken", "stripeSessionId",
  "keyPreview", "verifiedAt", "targetUrl", "findingTitle", "frequencyDays",
  "scheduleString", "lastScannedAt", "nextScanAt", "scanHour", "scanMinute",
  "scanWeekday", "lastError", "tokenHash", "expiresAt", "consumedAt", "scanId",
  "sourceIp", "userAgent", "receivedAt", "resolvedIp", "nmapVersion", "rawXml",
  "startedAt", "findingCategory", "updatedAt", "codeHash",
  // These five are not currently read through normalizeRow — they appear only
  // in write predicates (SET claimedAt = …, WHERE bucketKey = …) or in raw
  // pool.query results with explicitly named columns. They are listed anyway so
  // the map is COMPLETE against schema.sql rather than complete-for-today:
  // adding a `SELECT *` on one of these tables later would otherwise reintroduce
  // the silent-undefined bug, and the test that pins this cannot tell an
  // intentional omission from a forgotten one.
  "bucketKey", "claimedAt", "heartbeatAt", "hitAt", "jobParams",
] as const;

const LOWER_TO_CAMEL: Record<string, string> = Object.fromEntries(
  CAMEL_COLUMNS.map((c) => [c.toLowerCase(), c]),
);

// Exposed for the test (to assert no two camelCase columns collide on their
// lower-cased key, which would make the remap ambiguous).
export const _camelColumns = CAMEL_COLUMNS;
export const _lowerToCamel = LOWER_TO_CAMEL;

// Remap a Postgres row's lower-cased keys back to the camelCase the mappers
// expect. Keys with no camelCase counterpart (already all-lowercase columns like
// id/email/url/status) pass through untouched. Returns the input unchanged when
// it's null/undefined so callers can pipe `.get()` results straight through.
export function normalizeRow<T extends Record<string, any> | undefined | null>(row: T): T {
  if (!row) return row;
  const out: Record<string, any> = {};
  for (const [k, v] of Object.entries(row)) {
    out[LOWER_TO_CAMEL[k] ?? k] = v;
  }
  return out as T;
}

export function normalizeRows(rows: Array<Record<string, any>>): Array<Record<string, any>> {
  return rows.map((r) => normalizeRow(r));
}
