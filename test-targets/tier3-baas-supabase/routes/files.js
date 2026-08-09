// T3-Storage-001 (adapted — see the migration file's comment: real Supabase
// Storage normalizes "../" server-side, so a literal traversal payload
// doesn't work against the real engine). The realistic, common version of a
// Storage authorization bug is the same root cause as profiles.js/tokens.js:
// a backend route proxies Storage downloads via the SERVICE ROLE key
// without checking the requester's own identity against the object's owner
// — an IDOR/BOLA over file storage, provable the same way Tier 1/2's BOLA
// findings are (two identities, cross-access).
//
// /api/files/:ownerId/:filename — VULNERABLE: service role, no ownership
// check, so any caller supplying another user's ownerId gets their file.
//
// /api/files-safe/:filename — forwards the caller's own JWT so the real
// "bucket_id = 'user-files' AND owner = auth.uid()" storage policy applies;
// there's no ownerId parameter to manipulate at all, by construction.
const express = require('express');
const { supabaseAdmin, supabaseAsCaller } = require('../lib/supabaseClients');

const router = express.Router();
const BUCKET = 'user-files';

router.get('/api/files/:ownerId/:filename', async (req, res) => {
  const path = `${req.params.ownerId}/${req.params.filename}`;
  const { data, error } = await supabaseAdmin.storage.from(BUCKET).download(path);
  if (error) return res.status(404).json({ error: error.message });
  const text = await data.text();
  res.type('text/plain').send(text);
});

router.get('/api/files-safe/:filename', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
  const caller = supabaseAsCaller(authHeader);
  const { data: userData, error: userErr } = await caller.auth.getUser(authHeader.replace(/^Bearer\s+/i, ''));
  if (userErr || !userData?.user) return res.status(401).json({ error: 'Unauthorized' });
  const path = `${userData.user.id}/${req.params.filename}`;
  const { data, error } = await caller.storage.from(BUCKET).download(path);
  if (error) return res.status(404).json({ error: error.message });
  const text = await data.text();
  res.type('text/plain').send(text);
});

module.exports = router;
