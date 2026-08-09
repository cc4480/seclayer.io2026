// T2-Deser-001 (Insecure Deserialization) — adapted from the PRD's PHP
// unserialize()/magic-method example to its real Node.js equivalent:
// PROTOTYPE POLLUTION via an unguarded recursive merge. PHP's unserialize()
// has no direct Node analog (JS has no user-definable "wakeup" hook invoked
// by a generic deserializer), but naive recursive merging of attacker JSON —
// exactly what a real "restore this serialized blob" endpoint does — is a
// real, common, CVE-worthy Node vulnerability class with comparable impact
// (global behavior corruption, and in the right gadget chain, RCE).
//
// POST /api/restore-session base64-decodes + JSON-parses the blob, then
// merges it into a session object key-by-key with a plain `for...in` loop
// and no __proto__/constructor guard. Because bracket-notation assignment
// (target[key] = ...) DOES trigger the real prototype setter when
// key === '__proto__', a payload like {"__proto__":{"polluted":"yes"}}
// genuinely pollutes Object.prototype for the whole process — observable via
// GET /api/debug/polluted-check, a plain object literal in a separate,
// unrelated request.
const express = require('express');

const router = express.Router();

function unsafeMerge(target, src) {
  for (const key in src) {
    if (src[key] && typeof src[key] === 'object' && !Array.isArray(src[key])) {
      if (typeof target[key] !== 'object' || target[key] === null) target[key] = {};
      unsafeMerge(target[key], src[key]);
    } else {
      target[key] = src[key]; // VULNERABLE: no __proto__/constructor.prototype guard
    }
  }
  return target;
}

router.post('/api/restore-session', (req, res) => {
  const sessionData = req.body && req.body.sessionData;
  if (typeof sessionData !== 'string') return res.status(400).json({ error: 'sessionData required' });
  let decoded;
  try {
    decoded = JSON.parse(Buffer.from(sessionData, 'base64').toString('utf8'));
  } catch {
    return res.status(400).json({ error: 'invalid session data' });
  }
  const session = unsafeMerge({}, decoded);
  res.json({ success: true, session });
});

// Observable side effect for proving pollution: an unrelated endpoint
// returning a BRAND NEW plain object literal. If Object.prototype was
// polluted, this object inherits the polluted property despite never
// setting it itself.
router.get('/api/debug/polluted-check', (req, res) => {
  const freshObject = {};
  res.json({ polluted: freshObject.polluted !== undefined, value: freshObject.polluted });
});

module.exports = router;
