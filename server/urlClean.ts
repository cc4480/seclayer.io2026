// Shared URL-normalizer used by both DB backends (SQLite + Postgres) for
// suppression-rule matching. Extracted so the Postgres adapter can use it
// WITHOUT importing server/db.js (which instantiates SqliteDb at module load,
// opening the SQLite file — an unwanted side effect when running on Postgres).
export function cleanUrl(urlStr: string): string {
  try {
    return urlStr.replace(/https?:\/\//i, "").replace(/\/+$/, "").trim().toLowerCase();
  } catch {
    return String(urlStr || "").trim().toLowerCase();
  }
}
