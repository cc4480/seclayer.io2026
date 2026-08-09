// Tier 2 — Advanced Attack Chains intentionally-vulnerable benchmark app.
// Real Express + JWT code (not simulated responses) implementing the 8
// planted vulnerabilities + 4 negative controls in vulnerabilities.json, to
// verify what Seclayer's real scanner actually detects. NOT for production
// use, NOT for internet exposure — run it locally only.
//
//   cd test-targets/tier2-advanced-attack-chains && npm install && npm start
//   (listens on 127.0.0.1:<PORT>, default 4102)
const express = require('express');
const path = require('path');

const PORT = Number(process.argv[2] || process.env.VULN_PORT || 4102);

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Deliberately NO security headers, matching the other test-targets/ fixtures.
app.use(express.static(path.join(__dirname, 'public')));

app.use(require('./routes/login'));           // T2-NoSQLi-001
app.use(require('./routes/admin'));            // T2-PrivEsc-001 + T2-NC-002
app.use(require('./routes/upload'));           // T2-XXE-001
app.use(require('./routes/checkout'));         // T2-BizLogic-001 + T2-NC-003
app.use(require('./routes/documents'));        // T2-HorzPrivEsc-001
app.use(require('./routes/transfer'));         // T2-RaceCondition-001 + T2-NC-004
app.use(require('./routes/passwordReset'));    // T2-WeakCrypto-001 + T2-NC-001
app.use(require('./routes/restoreSession'));   // T2-Deser-001 (adapted: prototype pollution)

app.listen(PORT, '127.0.0.1', () => {
  console.log(`[tier2-advanced-attack-chains] listening on http://127.0.0.1:${PORT}`);
});
