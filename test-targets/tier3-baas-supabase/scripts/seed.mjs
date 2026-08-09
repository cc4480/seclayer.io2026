// One-time setup: creates two real Supabase Auth users (via the real GoTrue
// signup endpoint, so their JWTs are genuine and their auth.users rows are
// real — not hand-inserted), then seeds profiles/embeddings/session_tokens
// rows against their real user_ids using the service-role client. Run once
// after `supabase start`, before `npm start`.
//
// Usage: node --env-file=.env scripts/seed.mjs
import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = process.env.SUPABASE_URL;
const ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const anon = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false } });
const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, { auth: { persistSession: false } });

async function ensureUser(email, password) {
  const { data, error } = await anon.auth.signUp({ email, password });
  if (error && !/already registered/i.test(error.message)) throw error;
  if (data?.user) return { id: data.user.id, token: data.session?.access_token };
  // Already existed from a previous run — sign in instead to get id/token.
  const signIn = await anon.auth.signInWithPassword({ email, password });
  if (signIn.error) throw signIn.error;
  return { id: signIn.data.user.id, token: signIn.data.session.access_token };
}

const alice = await ensureUser('alice@tier3.test', 'AlicePass!2026');
const bob = await ensureUser('bob@tier3.test', 'BobPass!2026');
console.log('alice', alice.id);
console.log('bob', bob.id);

// Immediately after `supabase db reset`, PostgREST's cached schema/grants
// snapshot can be briefly stale — the first request or two right after a
// reset can 403 with "permission denied" even though the grant is correct,
// until PostgREST processes the reload notification. Retrying once after a
// short pause is enough; this is a startup race, not a real permission gap.
async function check(label, step) {
  let { error } = await step();
  if (error) {
    await new Promise((r) => setTimeout(r, 1500));
    ({ error } = await step());
  }
  if (error) console.error(`SEED STEP FAILED: ${label}:`, error.message);
}

await check('profiles', () => admin.from('profiles').upsert([
  { user_id: alice.id, email: 'alice@tier3.test', sensitive_data: 'alice-ssn-078-05-1120' },
  { user_id: bob.id, email: 'bob@tier3.test', sensitive_data: 'bob-ssn-078-05-1121' },
]));

await check('admin_config', () => admin.from('admin_config').upsert([
  { id: 1, setting: 'max_users', value: '1000' },
  { id: 2, setting: 'api_rate_limit', value: 'unlimited' },
]));
await check('admin_config_safe', () => admin.from('admin_config_safe').upsert([{ id: 1, setting: 'max_users', value: '1000' }]));

await check('embeddings', () => admin.from('embeddings').upsert([
  { user_id: alice.id, content: 'alice private notes about the widget project', embedding: [0.1, 0.2, 0.3] },
  { user_id: bob.id, content: 'bob private notes about the gadget project', embedding: [0.4, 0.5, 0.6] },
]));

await check('session_tokens', () => admin.from('session_tokens').upsert([
  { user_id: alice.id, token: 'fake-plaintext-session-token-alice' },
  { user_id: bob.id, token: 'fake-plaintext-session-token-bob' },
]));

// Uploaded AS each user (not via the service-role client) so Storage sets
// the `owner` column to their real auth.uid() — the safe route's RLS policy
// depends on that being correct, not null.
const aliceClient = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false }, global: { headers: { Authorization: `Bearer ${alice.token}` } } });
const bobClient = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false }, global: { headers: { Authorization: `Bearer ${bob.token}` } } });
await check('alice storage upload', () => aliceClient.storage.from('user-files').upload(`${alice.id}/notes.txt`, new Blob(['alice private file contents']), { upsert: true }));
await check('bob storage upload', () => bobClient.storage.from('user-files').upload(`${bob.id}/notes.txt`, new Blob(['bob private file contents']), { upsert: true }));

console.log('\nAlice token:', alice.token);
console.log('Bob token:', bob.token);
console.log('\nSeed complete.');
