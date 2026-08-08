// T1-AccessControl-001 — GET /admin/users only checks that SOME session
// exists (requireSession), never that it belongs to an admin, and returns
// every user's row including their plaintext password. The PRD's framing —
// "client hides the button, server never checks the role" — is a client-side
// concern that doesn't exist in this headless fixture; what matters for a
// black-box scanner is exactly what's implemented here: the server-side
// check is missing.
const express = require('express');
const db = require('../db');
const { requireSession } = require('../auth');

const router = express.Router();

router.get('/admin/users', requireSession, (req, res) => {
  const rows = db.prepare('SELECT id, username, password, email, role FROM users').all();
  res.json(rows); // VULNERABLE: no role check, leaks passwords to any logged-in user
});

module.exports = router;
