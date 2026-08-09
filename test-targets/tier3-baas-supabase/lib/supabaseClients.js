// Two Supabase clients, mirroring the two real ways a backend talks to
// Supabase. Which one a route uses IS the vulnerability or the fix — see
// each route file's comment.
const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL;

// SERVICE ROLE client: authenticates as the project itself and BYPASSES RLS
// entirely, by design (it's meant for trusted server-side jobs, never for
// serving a request on behalf of whoever happens to be calling your API).
const supabaseAdmin = createClient(SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
});

// Build an ANON-role client that forwards the CALLER's own Authorization
// header, so PostgREST evaluates RLS as that specific user — the correct
// pattern for a route acting "on behalf of" whoever is asking.
function supabaseAsCaller(authHeader) {
  return createClient(SUPABASE_URL, process.env.SUPABASE_ANON_KEY, {
    auth: { persistSession: false },
    global: { headers: authHeader ? { Authorization: authHeader } : {} },
  });
}

module.exports = { supabaseAdmin, supabaseAsCaller };
