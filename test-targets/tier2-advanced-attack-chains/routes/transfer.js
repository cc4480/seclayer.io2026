// T2-RaceCondition-001 — POST /api/transfer checks the balance, then (after
// an artificial delay that widens the race window so it's reliably
// reproducible in a test, not just theoretically possible) deducts it. Two
// concurrent requests can both pass the balance check before either deducts,
// letting the account go negative — a classic TOCTOU double-spend.
//
// T2-NC-004 (negative control) — /api/transfer-safe does the check-and-
// deduct SYNCHRONOUSLY with no yield point in between, which on Node's
// single-threaded event loop is naturally atomic: nothing can interleave
// without an explicit await/setTimeout/etc. between the read and the write.
const express = require('express');
const { ACCOUNTS, resetAccounts } = require('../db');

const router = express.Router();

router.post('/api/transfer', (req, res) => {
  const accountId = req.body && req.body.accountId;
  const amount = Number(req.body && req.body.amount);
  const account = ACCOUNTS[accountId];
  if (!account || !Number.isFinite(amount)) return res.status(400).json({ error: 'bad request' });
  if (account.balance < amount) return res.status(400).json({ error: 'insufficient funds' });
  // VULNERABLE: yield point between the check above and the deduction below.
  setTimeout(() => {
    account.balance -= amount;
    res.json({ success: true, newBalance: account.balance });
  }, 75);
});

router.post('/api/transfer-safe', (req, res) => {
  const accountId = req.body && req.body.accountId;
  const amount = Number(req.body && req.body.amount);
  const account = ACCOUNTS[accountId];
  if (!account || !Number.isFinite(amount)) return res.status(400).json({ error: 'bad request' });
  if (account.balance < amount) return res.status(400).json({ error: 'insufficient funds' }); // SAFE: no yield before the deduction below
  account.balance -= amount;
  res.json({ success: true, newBalance: account.balance });
});

router.get('/api/account/:id', (req, res) => {
  const account = ACCOUNTS[req.params.id];
  if (!account) return res.status(404).json({ error: 'not found' });
  res.json(account);
});

// Test-only convenience: reset the in-memory balance between race-condition
// test runs so results are repeatable.
router.post('/api/account/:id/reset', (req, res) => {
  resetAccounts();
  res.json({ success: true });
});

module.exports = router;
