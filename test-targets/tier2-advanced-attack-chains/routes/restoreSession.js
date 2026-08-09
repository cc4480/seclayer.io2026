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

// The app's OWN response-formatting config, a plain object read via bracket
// access below. This is the observable "gadget" a black-box scanner needs:
// modern Express (>=4.21) hardened its own `app.get('json spaces')` to ignore
// Object.prototype, so the framework no longer leaks the pollution — but an
// application that keeps its own settings object and reads a value out of it
// with unguarded bracket access (extremely common) is still fully exposed.
// `appResponseConfig['json spaces']` inherits a polluted Object.prototype
// value, so formatting flips from compact to indented once the prototype is
// polluted. This is a realistic app-level gadget, not bespoke instrumentation.
const appResponseConfig = {};

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

// Serialize using the app's own configured indentation, read with unguarded
// bracket access (the app-level gadget described above).
function sendConfigured(res, payload) {
  const spaces = appResponseConfig['json spaces'] || 0;
  res.type('application/json').send(JSON.stringify(payload, null, spaces));
}

router.post('/api/restore-session', (req, res) => {
  let decoded;
  if (req.body && typeof req.body.sessionData === 'string') {
    // Legacy "restore this serialized blob" shape (base64-wrapped) — kept so the
    // fixture still covers that variant.
    try {
      decoded = JSON.parse(Buffer.from(req.body.sessionData, 'base64').toString('utf8'));
    } catch {
      return res.status(400).json({ error: 'invalid session data' });
    }
  } else if (req.body && typeof req.body === 'object' && !Array.isArray(req.body)) {
    // Mainstream shape: a settings/session object deep-merged straight from the
    // request body — by far the more common real-world sink (config merge,
    // profile update, "PATCH my preferences"), and the one a generic scanner
    // can actually reach without knowing a bespoke wrapper field. A payload
    // like {"__proto__":{"json spaces":7}} pollutes Object.prototype here.
    decoded = req.body;
  } else {
    return res.status(400).json({ error: 'session data required' });
  }
  const session = unsafeMerge({}, decoded);
  sendConfigured(res, { success: true, session });
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
