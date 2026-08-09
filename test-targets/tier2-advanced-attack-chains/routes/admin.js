// T2-PrivEsc-001 target — the endpoint that pays off the alg:none bypass in
// ../auth.js's requireAuth: it checks req.user.role, but requireAuth having
// accepted an unverified token means an attacker can set role:"admin" in a
// self-issued, unsigned token and reach this data regardless of who they
// really are.
const express = require('express');
const { requireAuth, requireAuthHardened } = require('../auth');

const router = express.Router();

router.get('/api/admin/settings', requireAuth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
  res.json({ settings: { apiKey: 'fake-not-real', webhookSecret: 'fake-not-real', adminEmail: 'admin@tier2.test' } });
});

// T2-NC-002 negative control — same data, but gated by requireAuthHardened
// (algorithms locked to ['HS256'] only, short-lived token).
router.get('/api/admin/settings-hardened', requireAuthHardened, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
  res.json({ settings: { apiKey: 'fake-not-real', webhookSecret: 'fake-not-real', adminEmail: 'admin@tier2.test' } });
});

module.exports = router;
