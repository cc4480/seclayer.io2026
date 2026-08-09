// T4-SQLi-Regional-001 — classic string-concatenated SQL injection via the
// "estado" (Mexican state) query parameter, a realistic regional-filtering
// feature for cross-border commerce.
const express = require('express');
const db = require('../db');

const router = express.Router();

router.get('/api/merchants', (req, res) => {
  const estado = String(req.query.estado || '');
  try {
    // VULNERABLE: string-concatenated into the SQL text.
    const merchants = db.prepare(`SELECT * FROM merchants WHERE estado = '${estado}'`).all();
    res.json(merchants);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/api/merchants-safe', (req, res) => {
  const estado = String(req.query.estado || '');
  const merchants = db.prepare('SELECT * FROM merchants WHERE estado = ?').all(estado);
  res.json(merchants);
});

module.exports = router;
