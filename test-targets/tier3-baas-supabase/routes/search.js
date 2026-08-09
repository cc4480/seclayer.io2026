// T3-VectorDB-Injection-001 (adapted — see the migration file's comment).
// PostgREST's REST filter DSL doesn't expose pgvector's "<->" nearest-
// neighbor operator, so /api/search drops to a raw `pg` connection instead —
// and concatenates the query parameter directly into the SQL string. Real
// shape of how injection creeps back into an otherwise-parameterized BaaS
// stack: the ONE endpoint that needed raw SQL for a feature PostgREST can't
// express is the one an app commonly forgets to parameterize.
//
// /api/search-safe does the identical vector-adjacent lookup with a bound
// parameter instead of concatenation.
const express = require('express');
const { Pool } = require('pg');

const router = express.Router();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

router.get('/api/search', async (req, res) => {
  const query = String(req.query.query || '');
  // VULNERABLE: string-concatenated into the SQL text.
  const sql = `select id, user_id, content from embeddings where content ilike '%${query}%' limit 10`;
  try {
    const result = await pool.query(sql);
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/api/search-safe', async (req, res) => {
  const query = String(req.query.query || '');
  try {
    const result = await pool.query(
      'select id, user_id, content from embeddings where content ilike $1 limit 10',
      [`%${query}%`],
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
