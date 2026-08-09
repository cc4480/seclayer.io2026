// T4-i18n-Bypass-001 — the admin auth check is applied to the English route
// only. Same handler content either way; only the /es/ path skips
// requireAdmin entirely. Realistic root cause: i18n route trees are commonly
// generated per-locale (Next.js pages/[locale]/...), and it's easy to wire
// middleware onto one locale's route tree and forget the other.
//
// T4-NC-001 — /en/account and /es/account are both correctly gated the same
// way, proving a scanner that flags EVERY /es/* route as unprotected (rather
// than genuinely comparing per-route) would be reporting a false positive.
const express = require('express');
const { requireAdmin, requireSession } = require('../auth');

const router = express.Router();

const dashboardHtml = (locale) =>
  locale === 'es'
    ? '<!doctype html><html><body><h1>Panel de Administrador</h1><div id="admin-data"><p>Ingresos totales: $5,000 USD</p></div></body></html>'
    : '<!doctype html><html><body><h1>Admin Dashboard</h1><div id="admin-data"><p>Total revenue: $5,000 USD</p></div></body></html>';

router.get('/en/admin/dashboard', requireAdmin, (_req, res) => {
  res.type('html').send(dashboardHtml('en'));
});

// VULNERABLE: no requireAdmin at all on the Spanish route.
router.get('/es/admin/dashboard', (_req, res) => {
  res.type('html').send(dashboardHtml('es'));
});

const accountHtml = (locale) =>
  locale === 'es'
    ? '<!doctype html><html><body><h1>Mi Cuenta</h1></body></html>'
    : '<!doctype html><html><body><h1>My Account</h1></body></html>';

router.get('/en/account', requireSession, (_req, res) => res.type('html').send(accountHtml('en')));
router.get('/es/account', requireSession, (_req, res) => res.type('html').send(accountHtml('es')));

module.exports = router;
