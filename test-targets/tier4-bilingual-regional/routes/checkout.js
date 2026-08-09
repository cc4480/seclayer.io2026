// T4-Price-Manip-001 — /api/checkout trusts the client-supplied price AND
// currency instead of looking either up server-side, so submitting a
// mismatched (currency, price) pair — e.g. claiming MXN pricing while
// supplying a negligible price — is honored at face value.
//
// T4-NC-... (safe pair) — /api/checkout-safe looks up both price columns by
// productId and selects the one matching the requested currency, ignoring
// whatever price the client sent.
const express = require('express');
const db = require('../db');

const router = express.Router();

router.post('/api/checkout', (req, res) => {
  const items = Array.isArray(req.body && req.body.items) ? req.body.items : [];
  const currency = (req.body && req.body.currency) === 'MXN' ? 'MXN' : 'USD';
  let total = 0;
  for (const item of items) {
    const price = Number(item.price);
    const quantity = Number(item.quantity);
    if (!Number.isFinite(price) || !Number.isFinite(quantity)) continue;
    total += price * quantity; // VULNERABLE: client-supplied price trusted directly
  }
  res.json({ success: true, charged: Math.round(total * 100) / 100, currency, orderId: 'ord_laredo_' + Math.random().toString(36).slice(2) });
});

router.post('/api/checkout-safe', (req, res) => {
  const items = Array.isArray(req.body && req.body.items) ? req.body.items : [];
  const currency = (req.body && req.body.currency) === 'MXN' ? 'MXN' : 'USD';
  const column = currency === 'MXN' ? 'price_mxn' : 'price_usd';
  let total = 0;
  for (const item of items) {
    const product = db.prepare(`SELECT ${column} AS price FROM products WHERE id = ?`).get(item.productId);
    const quantity = Number(item.quantity);
    if (!product || !Number.isFinite(quantity)) continue;
    total += product.price * quantity; // SAFE: server-sourced price for the requested currency
  }
  res.json({ success: true, charged: Math.round(total * 100) / 100, currency, orderId: 'ord_laredo_' + Math.random().toString(36).slice(2) });
});

module.exports = router;
