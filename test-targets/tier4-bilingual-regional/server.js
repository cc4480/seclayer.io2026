// Tier 4 vulnerable-app benchmark fixture (bilingual/regional commerce).
// Real Express app, not simulated. Local use only — never expose this to
// the internet. See README.md.
const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const { login } = require('./auth');

const app = express();
const PORT = process.env.PORT || 4104;

// Captures the raw body (needed for HMAC signature verification in
// routes/webhook.js) alongside normal JSON parsing for every other route.
app.use(express.json({ verify: (req, _res, buf) => { req.rawBody = buf; } }));
app.use(cookieParser());
app.use('/public', express.static(path.join(__dirname, 'public')));

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/api/login', login);

// T4-Hardcoded-Creds-001 — the accidentally-served .env file, same
// exposure mechanism as Tier 3's T3-JWT-Secret-001 (Express's own
// dotfile-serving protection is explicitly overridden, modeling a real
// static-middleware misconfiguration).
app.get('/.env', (_req, res) => {
  res.type('text/plain').sendFile(path.join(__dirname, '.env'), { dotfiles: 'allow' });
});

app.use(require('./routes/admin'));
app.use(require('./routes/passwordReset'));
app.use(require('./routes/checkout'));
app.use(require('./routes/smsAuth'));
app.use(require('./routes/merchants'));
app.use(require('./routes/webhook'));

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Tier 4 fixture listening on http://127.0.0.1:${PORT}`);
});
