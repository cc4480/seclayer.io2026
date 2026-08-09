// T3-RLS-Bypass-001 (adapted — see supabase/migrations/00000000000001_tier3_schema.sql
// for why) + T3-NC-001.
//
// /api/profiles: uses the SERVICE ROLE key (bypasses RLS by design) to serve
// a request without checking who's actually asking. Any caller — even with
// no Authorization header at all — gets every user's row.
//
// /api/profiles-safe: forwards the CALLER's own JWT to PostgREST via the
// anon-role client, so the real "auth.uid() = user_id" RLS policy is
// evaluated as that specific user. This is also the endpoint T3-JWT-Secret-001
// targets: forging a token with someone else's user_id and a signature that
// verifies (because the signing secret leaked) still gets through, because
// this route correctly trusts whatever identity a validly-signed JWT claims.
const express = require('express');
const { supabaseAdmin, supabaseAsCaller } = require('../lib/supabaseClients');

const router = express.Router();

router.get('/api/profiles', async (_req, res) => {
  const { data, error } = await supabaseAdmin.from('profiles').select('*');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

router.get('/api/profiles-safe', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
  const { data, error } = await supabaseAsCaller(authHeader).from('profiles').select('*');
  if (error) return res.status(401).json({ error: error.message });
  res.json(data);
});

module.exports = router;
