// Tier 3 vulnerable-app benchmark fixture (Supabase BaaS). Real Supabase
// local dev stack underneath (Postgres + RLS, PostgREST, GoTrue Auth,
// Realtime, Storage) — not simulated. Local use only, never expose this to
// the internet. See README.md.
const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 4103;

app.use(express.json());
app.use('/public', express.static(path.join(__dirname, 'public')));

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// T3-JWT-Secret-001 — the "accidentally committed / served .env file"
// exposure this vuln's exploitation chain starts from. Serves the SAME file
// `node --env-file=.env` loads at boot, matching the real-world mistake this
// models (an Express static/route misconfiguration that serves the actual
// dotenv file the app itself reads its secrets from).
app.get('/.env', (_req, res) => {
  // Express's `send`/sendFile ignores dotfiles by default — real static-
  // middleware misconfigurations that leak a .env file typically come from
  // `express.static(root)` pointed at the wrong directory (the project root
  // instead of just /public) with `dotfiles: 'allow'` set, or a reverse
  // proxy serving the filesystem directly. Modeled here explicitly so the
  // fixture doesn't depend on Express's own default protection working
  // *against* the vulnerability it's supposed to demonstrate.
  res.type('text/plain').sendFile(path.join(__dirname, '.env'), { dotfiles: 'allow' });
});

// T3-Backup-Exposure-001 — publicly reachable, unauthenticated database
// backup. Linked from the homepage so it's crawler-discoverable, not just a
// fixed-path guess.
app.use('/backups', express.static(path.join(__dirname, 'backups')));

app.use(require('./routes/profiles'));
app.use(require('./routes/search'));
app.use(require('./routes/tokens'));
app.use(require('./routes/files'));

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Tier 3 fixture listening on http://127.0.0.1:${PORT}`);
});
