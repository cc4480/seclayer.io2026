// T3-EdgeFunc-001. Checks only for the PRESENCE of an Authorization header,
// never validates it. Real, common Edge Function bug: Supabase's API
// gateway only verifies a JWT for functions marked verify_jwt = true in
// config.toml; a function invoked with that check off (or that assumes the
// gateway already handled it) must validate the token itself, and this one
// doesn't.
Deno.serve(async (req: Request) => {
  const auth = req.headers.get('Authorization');
  if (!auth) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  // VULNERABLE: accepts ANY Authorization header, never verifies the JWT.
  return new Response(
    JSON.stringify({
      success: true,
      dataExported: 'sk_admin_secret_export_2026',
      timestamp: new Date().toISOString(),
    }),
    { headers: { 'Content-Type': 'application/json' } },
  );
});
