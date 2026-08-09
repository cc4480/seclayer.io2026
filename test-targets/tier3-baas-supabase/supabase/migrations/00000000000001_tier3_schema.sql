-- Tier 3 benchmark schema: real Postgres RLS, real pgvector, real Storage
-- policies. Mirrors TIER3_BAAS_SUPABASE_PRD.md's 9 planted vulnerabilities +
-- 4 negative controls, adapted where the PRD's specific technical claim
-- doesn't hold up against the real engine (see README.md's adaptation notes
-- for the reasoning per vuln — same discipline as Tier 1/2).

create extension if not exists vector;

-- === T3-RLS-Bypass-001 + T3-NC-001 (profiles) ===============================
-- The PRD's claimed mechanism (a NULL auth.uid() makes "auth.uid() =
-- user_id" fail OPEN) is not how Postgres RLS actually behaves: a NULL
-- result from a USING clause excludes the row, same as false — RLS is
-- fail-closed on NULL. The real, extremely common version of "RLS bypass" is
-- exactly what the PRD's OWN vulnerable code sample shows instead: a backend
-- API route using the SERVICE ROLE key (which bypasses RLS entirely) to
-- serve data with no authorization check of its own. That's what's built
-- here — see routes/profiles.js.
create table profiles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) not null,
  email text not null,
  sensitive_data text not null
);
alter table profiles enable row level security;
create policy "Users can only see their own profile"
  on profiles for select
  using (auth.uid() is not null and auth.uid() = user_id);
-- Own-row UPDATE, needed for the Realtime hijack verification (a user
-- legitimately updating their OWN profile is what broadcasts to every
-- subscriber — see scripts/verify-realtime-hijack.mjs).
create policy "Users can update their own profile"
  on profiles for update
  using (auth.uid() is not null and auth.uid() = user_id)
  with check (auth.uid() is not null and auth.uid() = user_id);
-- This CLI version does not auto-expose new tables to Data API roles without
-- an explicit GRANT (see config.toml's [api] comment) — service_role needs
-- one too despite bypassing RLS, or routes/profiles.js's service-role client
-- gets a bare "permission denied for table profiles" before RLS is ever
-- evaluated.
grant select, update on profiles to authenticated;
grant select, insert, update on profiles to service_role; -- insert: seed script only

-- === T3-AnonKey-Abuse-001 (admin_config) =====================================
-- Realistic, extremely common Supabase misconfig: a new table created
-- without ever restricting the anon role. RLS is opt-in in Postgres — a
-- table left without RLS enabled is readable by ANYONE holding the anon key,
-- which is itself public-by-design (shipped in every client bundle). No
-- malice needed, just a forgotten "ENABLE ROW LEVEL SECURITY".
create table admin_config (
  id serial primary key,
  setting text not null,
  value text not null
);
-- Deliberately NOT enabling RLS — the vulnerability IS the absence of it.
grant select on admin_config to anon, authenticated, service_role;
grant insert, update on admin_config to service_role; -- seed script only

-- === T3-NC-001, second instance: same table, properly locked down ==========
create table admin_config_safe (
  id serial primary key,
  setting text not null,
  value text not null
);
alter table admin_config_safe enable row level security;
create policy "Only authenticated users can read admin_config_safe"
  on admin_config_safe for select
  using (auth.role() = 'authenticated');
grant select on admin_config_safe to anon, authenticated, service_role;
grant insert, update on admin_config_safe to service_role; -- seed script only

-- === T3-VectorDB-Injection-001 (embeddings) ==================================
-- Real pgvector column (dimension kept small — this is a fixture, not a real
-- embedding model). The vulnerability lives in the application layer
-- (routes/search.js): user input concatenated into a raw SQL string executed
-- over a direct `pg` connection, bypassing PostgREST's parameterized filter
-- DSL entirely. Realistic shape — PostgREST's REST filter syntax doesn't
-- expose pgvector's "<->" nearest-neighbor operator, so apps commonly drop
-- to a raw SQL function/route for vector search, which is exactly where
-- unparameterized concatenation creeps back in.
create table embeddings (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) not null,
  content text not null,
  embedding vector(3) not null
);
-- routes/search.js queries this over a direct `pg` connection as the
-- postgres superuser (that IS the vulnerability's mechanism), so it needs no
-- PostgREST-role grant — this is only for the seed script's insert. UPDATE is
-- granted too because the seed uses upsert (INSERT ... ON CONFLICT DO UPDATE),
-- which PostgreSQL requires UPDATE privilege for even on a first, conflict-free
-- insert — without it the seed fails "permission denied for table embeddings".
grant select, insert, update on embeddings to service_role;

-- === T3-Unlogged-001 (session_tokens) =========================================
create unlogged table session_tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) not null,
  token text not null,
  created_at timestamptz not null default now()
);
grant select, insert, update on session_tokens to service_role; -- update: seed upsert (see embeddings note)

-- === T3-Storage-001 + T3-NC-004 (storage bucket + policy) ====================
-- Real Supabase Storage normalizes/rejects literal "../" path traversal
-- server-side (it isn't naively vulnerable to that in the current engine —
-- same story as Tier 2's jsonwebtoken alg:none hardening). The realistic,
-- common real-world version of a Storage authorization bug is instead the
-- SAME root cause as T3-RLS-Bypass-001/T3-Unlogged-001: a backend route
-- proxying Storage downloads via the SERVICE ROLE key without checking the
-- requester's own identity against the object's owner — see routes/files.js.
insert into storage.buckets (id, name, public) values ('user-files', 'user-files', false);

create policy "Users can access their own files via signed access"
  on storage.objects for select
  using (bucket_id = 'user-files' and owner = auth.uid());
create policy "Users can upload their own files"
  on storage.objects for insert
  with check (bucket_id = 'user-files' and owner = auth.uid());

-- === T3-Realtime-Hijack-001 ===================================================
-- Real Supabase Realtime footgun: adding a table to the supabase_realtime
-- publication broadcasts EVERY row change to EVERY subscriber holding a
-- valid (any) JWT — Postgres Changes authorization is checked at
-- subscribe-time against the anon/authenticated ROLE, not per-row against
-- RLS, unless the table is migrated to the newer private-channel model. Any
-- authenticated user who subscribes sees every other user's profile changes.
alter publication supabase_realtime add table profiles;
