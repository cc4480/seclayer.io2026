import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { runAggressiveProbes } from './aggressiveProbes.js';
import { probeSsti } from './aggressive/ssti.js';
import { probePathTraversal } from './aggressive/pathTraversal.js';
import { probeOpenRedirect } from './aggressive/openRedirect.js';
import { probeCrlf } from './aggressive/crlfInjection.js';
import { probeCors } from './aggressive/cors.js';
import { probeXxe } from './aggressive/xxe.js';
import { probeNoSql } from './aggressive/nosql.js';
import { isProven } from './scoring.js';
import type { ProbeContext } from './redTeam/types.js';
import type { OobCollaborator } from './oob.js';
import type { OobEvent } from '../src/types.js';

// The aggressive probes fetch through safeFetch / guardedFetch, both of which
// block loopback unless the dev-only SCAN_DEV_ALLOW_HOSTS escape hatch names this
// exact host:port. Same harness as redTeamProbes.test.ts so the units run against
// an owned local target with no real network access. (guardedFetch — used by the
// header-level open-redirect and CRLF probes — honors the same allowlist at the
// dispatcher's connect lookup, so one helper covers every probe.)
async function withServer(handler: http.RequestListener, fn: (port: number) => Promise<void>) {
  const server = http.createServer(handler);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as any).port;
  const prevEnv = process.env.NODE_ENV;
  const prevAllow = process.env.SCAN_DEV_ALLOW_HOSTS;
  try {
    process.env.NODE_ENV = 'development';
    process.env.SCAN_DEV_ALLOW_HOSTS = `127.0.0.1:${port}`;
    await fn(port);
  } finally {
    if (prevEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prevEnv;
    if (prevAllow === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS; else process.env.SCAN_DEV_ALLOW_HOSTS = prevAllow;
    await new Promise<void>((r) => server.close(() => r()));
  }
}

function ctxFor(port: number, extra: Partial<ProbeContext> = {}): ProbeContext {
  return {
    url: `http://127.0.0.1:${port}`,
    fuzzHeaders: { 'User-Agent': 'test', 'Cache-Control': 'no-cache' },
    ...extra,
  };
}

// Read a request body to completion (the NoSQL probe POSTs JSON credentials).
function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => resolve(raw));
  });
}

// A fake out-of-band collaborator for the XXE probe: issue() mints a fixed token
// and poll() resolves with whatever event we seed (or null for "no callback").
// The proof the probe stores is the collaborator record carrying this exact
// token, so a token match is the same guarantee the real collaborator provides.
const OOB_TOKEN = 'a'.repeat(48);
function fakeOob(event: OobEvent | null): OobCollaborator {
  return {
    baseUrl: 'http://oob.test',
    issue: () => ({ token: OOB_TOKEN, url: `http://oob.test/api/oob/${OOB_TOKEN}` }),
    poll: async () => event,
  };
}
function oobEvent(): OobEvent {
  return {
    id: 'evt-1',
    token: OOB_TOKEN,
    method: 'GET',
    sourceIp: '203.0.113.7',
    path: `/api/oob/${OOB_TOKEN}`,
    userAgent: 'Java/17.0.1',
    receivedAt: new Date().toISOString(),
  };
}

// --- SSTI ---------------------------------------------------------------------

test('probeSsti PROVES injection when the engine evaluates the expression (arithmetic oracle)', async () => {
  // A vulnerable template app: it renders {{A*B}} to the COMPUTED product and
  // never echoes the raw expression — exactly what the oracle looks for.
  await withServer((req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    const name = u.searchParams.get('name') || '';
    const m = /\{\{(\d+)\*(\d+)\}\}/.exec(name);
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!doctype html><html><body>Hello ${m ? Number(m[1]) * Number(m[2]) : 'guest'}</body></html>`);
  }, async (port) => {
    const finding = await probeSsti(ctxFor(port));
    assert.ok(finding, 'expected an SSTI finding');
    assert.equal(finding!.severity, 'critical');
    assert.match(finding!.testName, /Server-Side Template Injection/);
    // PROVEN invariant: the quoted product is literally present in the receipt.
    assert.ok(isProven(finding!), 'SSTI finding must carry a PROVEN receipt');
  });
});

test('probeSsti returns null when input is merely reflected, not evaluated (no false positive)', async () => {
  // Echoes the raw {{A*B}} back verbatim — reflection, not template evaluation.
  await withServer((req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!doctype html><html><body>Hello ${u.searchParams.get('name') || ''}</body></html>`);
  }, async (port) => {
    assert.equal(await probeSsti(ctxFor(port)), null, 'plain reflection must not be reported as SSTI');
  });
});

// --- Path traversal / LFI -----------------------------------------------------

test('probePathTraversal PROVES LFI when a traversal payload returns /etc/passwd', async () => {
  await withServer((req, res) => {
    const requested = [...new URL(req.url || '/', 'http://127.0.0.1').searchParams.values()].join('|');
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    if (/etc\/passwd/i.test(requested)) {
      res.end('root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n');
    } else {
      res.end('welcome');
    }
  }, async (port) => {
    const finding = await probePathTraversal(ctxFor(port));
    assert.ok(finding, 'expected a path-traversal finding');
    assert.equal(finding!.severity, 'critical');
    assert.match(finding!.testName, /Path Traversal/);
    assert.ok(isProven(finding!), 'LFI finding must carry a PROVEN receipt');
  });
});

test('probePathTraversal returns null when no system file is returned (no false positive)', async () => {
  await withServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><body>no files here</body></html>');
  }, async (port) => {
    assert.equal(await probePathTraversal(ctxFor(port)), null);
  });
});

// --- Open redirect ------------------------------------------------------------

test('probeOpenRedirect PROVES an open redirect to an attacker host (Location header)', async () => {
  // Reflects the "next" parameter straight into a 3xx Location — the classic flaw.
  await withServer((req, res) => {
    const dest = new URL(req.url || '/', 'http://127.0.0.1').searchParams.get('next');
    if (dest) { res.writeHead(302, { Location: dest }); res.end(); return; }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('home');
  }, async (port) => {
    const finding = await probeOpenRedirect(ctxFor(port));
    assert.ok(finding, 'expected an open-redirect finding');
    assert.equal(finding!.severity, 'medium');
    assert.match(finding!.testName, /Open Redirect/);
    assert.ok(isProven(finding!), 'open-redirect finding must carry a PROVEN receipt');
  });
});

test('probeOpenRedirect returns null for a same-site redirect (no false positive)', async () => {
  // Always redirects to a same-origin path, ignoring the supplied target.
  await withServer((_req, res) => {
    res.writeHead(302, { Location: '/home' });
    res.end();
  }, async (port) => {
    assert.equal(await probeOpenRedirect(ctxFor(port)), null, 'a same-site redirect must not be flagged');
  });
});

// --- CRLF / response-header injection ------------------------------------------

test('probeCrlf PROVES header injection when an injected header is reflected', async () => {
  // Simulates the vuln's effect: input carrying a CRLF + custom header lands as a
  // real response header (a sanitized app would strip it and never emit it).
  await withServer((req, res) => {
    const decoded = decodeURIComponent(req.url || '');
    const m = /(x-seclayer-crlf-[0-9a-f]+):\s*injected/i.exec(decoded);
    const headers: Record<string, string> = { 'Content-Type': 'text/html' };
    if (m) headers[m[1]] = 'injected';
    res.writeHead(200, headers);
    res.end('ok');
  }, async (port) => {
    const finding = await probeCrlf(ctxFor(port));
    assert.ok(finding, 'expected a CRLF finding');
    assert.equal(finding!.severity, 'high');
    assert.match(finding!.testName, /CRLF/);
    assert.ok(isProven(finding!), 'CRLF finding must carry a PROVEN receipt');
  });
});

test('probeCrlf returns null when the injected header is not reflected (no false positive)', async () => {
  await withServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('ok');
  }, async (port) => {
    assert.equal(await probeCrlf(ctxFor(port)), null);
  });
});

// --- CORS misconfiguration -----------------------------------------------------

test('probeCors PROVES the danger when the app reflects Origin AND allows credentials', async () => {
  await withServer((req, res) => {
    const origin = req.headers.origin;
    const headers: Record<string, string> = { 'Content-Type': 'text/html' };
    if (origin) {
      headers['Access-Control-Allow-Origin'] = String(origin);
      headers['Access-Control-Allow-Credentials'] = 'true';
    }
    res.writeHead(200, headers);
    res.end('ok');
  }, async (port) => {
    const finding = await probeCors(ctxFor(port));
    assert.ok(finding, 'expected a CORS finding');
    assert.equal(finding!.severity, 'high');
    assert.match(finding!.testName, /CORS Misconfiguration/);
    assert.ok(isProven(finding!), 'CORS finding must carry a PROVEN receipt');
  });
});

test('probeCors returns null for wildcard-with-credentials (browser-ignored, deliberately not flagged)', async () => {
  await withServer((_req, res) => {
    res.writeHead(200, {
      'Content-Type': 'text/html',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Credentials': 'true',
    });
    res.end('ok');
  }, async (port) => {
    assert.equal(await probeCors(ctxFor(port)), null, 'ACAO:* + credentials is ignored by browsers and must not be flagged');
  });
});

// --- XXE (out-of-band) ---------------------------------------------------------

test('probeXxe PROVES XXE when the target calls back to the collaborator', async () => {
  // The POSTs to the target may return anything (the callback is the proof); the
  // seeded collaborator event stands in for the target reaching our unique URL.
  await withServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
  }, async (port) => {
    const finding = await probeXxe(ctxFor(port, { oob: fakeOob(oobEvent()), scanId: 'scan-test' }));
    assert.ok(finding, 'expected an XXE finding');
    assert.equal(finding!.severity, 'critical');
    assert.match(finding!.testName, /XML External Entity/);
    // The out-of-band receipt must literally carry our correlation token.
    assert.ok(isProven(finding!), 'XXE finding must carry a PROVEN out-of-band receipt');
  });
});

test('probeXxe returns null when no callback arrives (no false positive)', async () => {
  await withServer((_req, res) => {
    res.writeHead(200);
    res.end('ok');
  }, async (port) => {
    assert.equal(await probeXxe(ctxFor(port, { oob: fakeOob(null) })), null, 'no callback means no XXE');
  });
});

test('probeXxe no-ops when no out-of-band collaborator is configured', async () => {
  // Must short-circuit before issuing any request — no server needed.
  assert.equal(await probeXxe({ url: 'http://127.0.0.1:9/', fuzzHeaders: {} }), null);
});

// --- NoSQL operator injection --------------------------------------------------

test('probeNoSql PROVES an auth bypass when an operator object authenticates but strings do not', async () => {
  await withServer(async (req, res) => {
    const raw = await readBody(req);
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    if (u.pathname !== '/api/login') { res.writeHead(404); res.end('{}'); return; }
    let body: any = {};
    try { body = JSON.parse(raw); } catch { /* ignore */ }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    // Vulnerable: an operator object slips through the query and authenticates,
    // while ordinary string credentials are rejected — the differential the probe needs.
    if (body && typeof body.username === 'object') {
      res.end(JSON.stringify({ authenticated: true, token: 'sess-xyz' }));
    } else {
      res.end(JSON.stringify({ authenticated: false, error: 'invalid credentials' }));
    }
  }, async (port) => {
    const finding = await probeNoSql(ctxFor(port));
    assert.ok(finding, 'expected a NoSQL finding');
    assert.equal(finding!.severity, 'critical');
    assert.match(finding!.testName, /NoSQL Injection/);
    assert.equal(finding!.evidence!.method, 'differential');
    assert.ok(isProven(finding!), 'NoSQL finding must carry a PROVEN differential receipt');
  });
});

test('probeNoSql returns null when the endpoint authenticates any input (differential guard, no FP)', async () => {
  // Authenticates everything — benign strings already pass, so there is no clean
  // signal and the probe must NOT report an injection.
  await withServer(async (req, res) => {
    await readBody(req);
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    if (u.pathname !== '/api/login') { res.writeHead(404); res.end('{}'); return; }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ authenticated: true }));
  }, async (port) => {
    assert.equal(await probeNoSql(ctxFor(port)), null, 'an endpoint that authenticates anything must not be flagged');
  });
});

// --- Orchestrator isolation ----------------------------------------------------

test('runAggressiveProbes isolates a throwing probe and still returns other findings', async () => {
  // The XXE probe throws (its collaborator.issue() blows up, outside the probe's
  // own try/catch), while the target is vulnerable to path traversal. The
  // orchestrator must swallow the XXE failure and still surface the LFI finding —
  // proving one probe's error never aborts the rest.
  const throwingOob: OobCollaborator = {
    baseUrl: '',
    issue: () => { throw new Error('boom'); },
    poll: async () => null,
  };
  const prevWarn = console.warn;
  console.warn = () => {}; // silence the expected "[aggressive] probe … failed" line
  try {
    await withServer((req, res) => {
      const requested = [...new URL(req.url || '/', 'http://127.0.0.1').searchParams.values()].join('|');
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(/etc\/passwd/i.test(requested) ? 'root:x:0:0:root:/root:/bin/bash\n' : 'welcome');
    }, async (port) => {
      const findings = await runAggressiveProbes(`http://127.0.0.1:${port}`, { 'User-Agent': 'test' }, { oob: throwingOob });
      assert.ok(
        findings.some((f) => /Path Traversal/i.test(f.testName)),
        'the path-traversal finding must survive the XXE probe throwing',
      );
    });
  } finally {
    console.warn = prevWarn;
  }
});
