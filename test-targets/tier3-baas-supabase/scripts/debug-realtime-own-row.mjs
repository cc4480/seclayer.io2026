// Debug-only: does Alice receive postgres_changes for HER OWN row? Confirms
// the broadcast pipe itself works, isolating whether RLS is gating it.
import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = process.env.SUPABASE_URL;
const ANON_KEY = process.env.SUPABASE_ANON_KEY;

const aliceAuth = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
const { data: aliceSession, error: aliceErr } = await aliceAuth.auth.signInWithPassword({ email: 'alice@tier3.test', password: 'AlicePass!2026' });
if (aliceErr) throw aliceErr;

let received = null;
const channel = aliceAuth
  .channel('public:profiles')
  .on('postgres_changes', { event: 'UPDATE', schema: 'public', table: 'profiles' }, (payload) => { received = payload; })
  .subscribe((status, err) => console.log('subscribe status:', status, err?.message || ''));

await new Promise((r) => setTimeout(r, 4000));

const upd = await aliceAuth.from('profiles').update({ sensitive_data: `alice-updated-${Date.now()}` }).eq('user_id', aliceSession.user.id).select();
console.log('alice update result:', JSON.stringify(upd.data), upd.error?.message || '');

await new Promise((r) => setTimeout(r, 3000));

console.log(received ? 'RECEIVED OWN-ROW UPDATE: ' + JSON.stringify(received.new) : 'NOT received (own row)');
await aliceAuth.removeChannel(channel);
process.exit(0);
