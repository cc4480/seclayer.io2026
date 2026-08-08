// Tier 1 — OWASP Foundation intentionally-vulnerable benchmark app. Real
// Express + SQLite code (not simulated responses) implementing the 7 planted
// vulnerabilities + 3 negative controls in vulnerabilities.json, to verify
// what Seclayer's real scanner actually detects. NOT for production use, NOT
// for internet exposure — run it locally only.
//
//   cd test-targets/tier1-owasp-foundation && npm install && npm start
//   (listens on 127.0.0.1:<PORT>, default 4101)
//
// Then point Seclayer at it with SCAN_DEV_ALLOW_HOSTS covering that port —
// see the main repo's test-targets/README-style comments in
// test-targets/vulnerable-app.mjs for the exact env vars.
const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');

const { login, loginHardened, loginLimiter } = require('./auth');
const usersRoute = require('./routes/users');
const profileRoute = require('./routes/profile');
const postsRoute = require('./routes/posts');
const invoicesRoute = require('./routes/invoices');
const adminRoute = require('./routes/admin');
const settingsRoute = require('./routes/settings');

const PORT = Number(process.argv[2] || process.env.VULN_PORT || 4101);

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// Deliberately NO security headers (no CSP/HSTS/X-Frame-Options/etc.) so the
// passive IAST header checks also have something real to flag, matching the
// rest of the test-targets/ fixtures.
app.use(express.static(path.join(__dirname, 'public')));

app.post('/login', loginLimiter, login); // T1-Auth-001 weak token; T1-NC-002 rate limit
app.post('/login-hardened', loginHardened); // T1-NC-003 negative control

app.use(usersRoute); // T1-SQLi-001
app.use(profileRoute); // T1-XSS-Reflected-001
app.use(postsRoute); // T1-XSS-Stored-001 + T1-NC-001
app.use(invoicesRoute); // T1-IDOR-001
app.use(adminRoute); // T1-AccessControl-001
app.use(settingsRoute); // T1-DataExposure-001

app.listen(PORT, '127.0.0.1', () => {
  console.log(`[tier1-owasp-foundation] listening on http://127.0.0.1:${PORT}`);
});
