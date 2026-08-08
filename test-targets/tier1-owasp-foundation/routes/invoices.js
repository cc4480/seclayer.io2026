// T1-IDOR-001 — GET /api/invoice/:id requires SOME valid session (so it isn't
// simply "unauthenticated"), but never checks that the session's user actually
// owns the invoice. Two seeded users/invoices (see db.js: user 2 owns invoice
// 1, user 3 owns invoice 2) so a two-identity scan can prove user A reading
// user B's invoice — same shape as the existing test-targets/vulnerable-app.mjs
// BOLA orders demo.
const express = require('express');
const db = require('../db');
const { requireSession } = require('../auth');

const router = express.Router();

router.get('/api/invoice/:id', requireSession, (req, res) => {
  const invoice = db.prepare('SELECT * FROM invoices WHERE id = ?').get(req.params.id);
  if (!invoice) return res.status(404).json({ error: 'not found' });
  res.json(invoice); // VULNERABLE: no check that invoice.user_id === req.userId
});

module.exports = router;
