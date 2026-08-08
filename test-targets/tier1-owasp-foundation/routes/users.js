// T1-SQLi-001 — GET /api/users?search= builds the query by direct string
// concatenation. A quote in `search` breaks out of the LIKE literal; real
// SQLite then either throws a genuine syntax error (surfaced back to the
// client) or, for `' OR '1'='1`, returns every row regardless of the search
// term — both are the real, unmodified behavior of the vulnerable query
// below, not a simulated response.
const express = require('express');
const db = require('../db');

const router = express.Router();

router.get('/api/users', (req, res) => {
  const search = req.query.search || '';
  const query = `SELECT id, username, email, role FROM users WHERE username LIKE '%${search}%'`;
  try {
    const rows = db.prepare(query).all();
    res.json(rows);
  } catch (err) {
    // Real SQLite error message, unmodified — matches the PRD's expected
    // "reveals table/column names or syntax error" proof.
    res.status(500).json({ error: `Database error: ${err.message}` });
  }
});

module.exports = router;
