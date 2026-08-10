// Convert better-sqlite3-style '?' placeholders to Postgres positional
// placeholders ('$1', '$2', ...). This lets the future Postgres adapter reuse
// the EXACT SQL strings the SQLite layer already uses (server/db.ts) instead of
// hand-rewriting 115 queries' placeholders — the single biggest source of risk
// and churn in the adapter, eliminated.
//
// A '?' inside a single-quoted SQL string literal is left untouched (with the
// standard '' escaping honored), so a literal question mark in SQL text isn't
// mistaken for a placeholder.
export function toPositional(sql: string): string {
  let out = "";
  let n = 0;
  let inString = false;
  for (let i = 0; i < sql.length; i++) {
    const c = sql[i];
    if (inString) {
      out += c;
      if (c === "'") {
        if (sql[i + 1] === "'") {
          // Escaped single quote ('') inside a literal — consume both, stay in string.
          out += "'";
          i++;
        } else {
          inString = false;
        }
      }
    } else if (c === "'") {
      inString = true;
      out += c;
    } else if (c === "?") {
      out += "$" + ++n;
    } else {
      out += c;
    }
  }
  return out;
}
