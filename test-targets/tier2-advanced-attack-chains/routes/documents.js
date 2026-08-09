// T2-HorzPrivEsc-001 — GET /api/document/:id/share requires SOME valid JWT
// (requireAuth), but never checks that the token's own subject owns the
// requested document — any authenticated user can read any document by ID.
// Same shape as Tier 1's invoice IDOR; two seeded owners (alice → 1001,
// bob → 1002) so a two-identity scan can prove alice reading bob's document.
const express = require('express');
const { DOCUMENTS } = require('../db');
const { requireAuth } = require('../auth');

const router = express.Router();

router.get('/api/document/:id/share', requireAuth, (req, res) => {
  const doc = DOCUMENTS[req.params.id];
  if (!doc) return res.status(404).json({ error: 'not found' });
  res.json(doc); // VULNERABLE: no check that doc.owner === req.user.sub
});

module.exports = router;
