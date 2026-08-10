// The minimal Postgres client surface the adapter needs, so server/pgDb.ts has
// NO hard dependency on `pg` (kept out of the adapter + its tests). The real
// `pg` Pool/PoolClient satisfy these structurally:
//   * pg.Pool.query(text, params)   -> { rows, rowCount }
//   * pg.Pool.connect()             -> PoolClient (query + release)
// Tests inject a mock implementing PgPool.
export interface PgResult {
  rows: any[];
  rowCount: number | null;
}

export interface PgQueryable {
  query(text: string, params?: any[]): Promise<PgResult>;
}

export interface PgPoolClient extends PgQueryable {
  release(): void;
}

export interface PgPool extends PgQueryable {
  connect(): Promise<PgPoolClient>;
  end(): Promise<void>;
}
