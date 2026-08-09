// T2-NoSQLi-001 — POST /api/login treats an OBJECT credential value (e.g.
// {"$ne": null}) as "matches anything", exactly the MongoDB-operator-bypass
// pattern: real string credentials are checked properly, but an operator
// object bypasses the check entirely and authenticates as the first user.
// /api/login is one of Seclayer's own fixed candidate login paths (see
// server/aggressive/nosql.ts's LOGIN_PATHS), so this is deliberately at that
// exact path rather than the PRD's originally-suggested /api/query.
const express = require('express');
const { USERS } = require('../db');
const { issueToken } = require('../auth');

const router = express.Router();

const isOperatorObject = (v) => v !== null && typeof v === 'object';

router.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};

  if (isOperatorObject(username) || isOperatorObject(password)) {
    // VULNERABLE: an operator-shaped value bypasses the credential check
    // entirely — authenticate as the first seeded user.
    const user = USERS.alice;
    return res.json({ authenticated: true, token: issueToken(user.username, user.role), username: user.username });
  }

  const user = USERS[username];
  if (!user || user.password !== password) {
    return res.status(401).json({ authenticated: false, error: 'invalid credentials' });
  }
  res.json({ authenticated: true, token: issueToken(user.username, user.role), username: user.username });
});

module.exports = router;
