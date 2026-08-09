// T3-NC-002 (edge function variant) — the hardened counterpart to
// sensitive-task: actually verifies the JWT's HS256 signature against the
// real Supabase Auth signing secret before doing anything. Minimal,
// dependency-free HMAC-SHA256 verification via Web Crypto (available
// natively in the Deno edge runtime) — no external JWT library needed for a
// single-algorithm check.
function b64urlToBytes(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/').padEnd(b64url.length + ((4 - (b64url.length % 4)) % 4), '=');
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function verifyHs256(token: string, secret: string): Promise<boolean> {
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [headerB64, payloadB64, sigB64] = parts;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  const signature = b64urlToBytes(sigB64);
  const data = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const valid = await crypto.subtle.verify('HMAC', key, signature, data);
  if (!valid) return false;
  const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(payloadB64)));
  if (typeof payload.exp === 'number' && payload.exp < Math.floor(Date.now() / 1000)) return false;
  return true;
}

Deno.serve(async (req: Request) => {
  const auth = req.headers.get('Authorization');
  const token = auth?.replace(/^Bearer\s+/i, '');
  const secret = Deno.env.get('JWT_SECRET') ?? '';
  if (!token || !(await verifyHs256(token, secret))) {
    return new Response(JSON.stringify({ error: 'Invalid token' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  return new Response(
    JSON.stringify({ success: true, dataExported: 'sk_admin_secret_export_2026' }),
    { headers: { 'Content-Type': 'application/json' } },
  );
});
