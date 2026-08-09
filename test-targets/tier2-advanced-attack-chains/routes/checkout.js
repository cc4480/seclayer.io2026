// T2-BizLogic-001 — POST /api/checkout trusts the client-supplied item price
// instead of looking it up server-side, so submitting a lower price is
// honored at face value.
//
// T2-NC-003 (negative control) — /api/checkout-safe looks the price up from
// PRODUCTS by productId and ignores whatever price the client sent.
const express = require('express');
const { PRODUCTS } = require('../db');

const router = express.Router();

router.post('/api/checkout', (req, res) => {
  const items = Array.isArray(req.body && req.body.items) ? req.body.items : [];
  let total = 0;
  for (const item of items) {
    const price = Number(item.price);
    const quantity = Number(item.quantity);
    if (!Number.isFinite(price) || !Number.isFinite(quantity)) continue;
    total += price * quantity; // VULNERABLE: client-supplied price trusted directly
  }
  res.json({ success: true, chargeAmount: Math.round(total * 100) / 100, orderId: 'ord_' + Math.random().toString(36).slice(2) });
});

router.post('/api/checkout-safe', (req, res) => {
  const items = Array.isArray(req.body && req.body.items) ? req.body.items : [];
  let total = 0;
  for (const item of items) {
    const product = PRODUCTS[item.productId];
    const quantity = Number(item.quantity);
    if (!product || !Number.isFinite(quantity)) continue;
    total += product.price * quantity; // SAFE: server-sourced price
  }
  res.json({ success: true, chargeAmount: Math.round(total * 100) / 100, orderId: 'ord_' + Math.random().toString(36).slice(2) });
});

module.exports = router;
