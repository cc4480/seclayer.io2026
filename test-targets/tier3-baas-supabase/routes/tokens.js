// T3-Unlogged-001. Same root cause as profiles.js: a route uses the SERVICE
// ROLE key without checking who's asking, this time exposing the raw
// plaintext session_tokens table (itself UNLOGGED — chosen for
// speed/throughput, a real, common Postgres footgun that has nothing to do
// with the exposure but compounds it: the tokens aren't even hashed).
const express = require('express');
const { supabaseAdmin } = require('../lib/supabaseClients');

const router = express.Router();

router.get('/api/tokens', async (_req, res) => {
  const { data, error } = await supabaseAdmin.from('session_tokens').select('*');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

module.exports = router;
