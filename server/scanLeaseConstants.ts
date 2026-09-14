// Leaf module (no imports) for scan-lease constants shared by both database
// backends. It lives apart from db.ts on purpose: db.ts has a top-level side
// effect (`export const db = createDb()`) that constructs the Postgres adapter,
// and pgDb.ts needs this constant. If pgDb.ts imported it from db.ts, the two
// would form an import cycle — and because db.ts constructs `PostgresDb` at load
// time, importing pgDb.ts first (as the Postgres integration tests do, with
// DATABASE_URL set) crashed with "Cannot access 'PostgresDb' before
// initialization" (TDZ). Keeping the constant in a leaf both files import breaks
// that cycle.

// How long a scan's lease may go unrefreshed before recovery treats its owner
// as dead. Comfortably longer than the heartbeat interval so a slow tick, a
// long probe or a brief database blip never orphans a healthy scan.
export const STALE_LEASE_MS = 5 * 60 * 1000;
