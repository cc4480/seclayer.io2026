// T2-XXE-001 — POST /upload parses a posted XML body and, if it declares an
// external entity with an http(s) SYSTEM identifier, "resolves" it by
// fetching that URL server-side. /upload is one of Seclayer's own fixed XXE
// candidate paths (see server/aggressive/xxe.ts's XML_PATHS). Mirrors the
// exact mechanism test-targets/vulnerable-app.mjs already uses (proven
// working against the out-of-band collaborator).
const express = require('express');

const router = express.Router();

router.post('/upload', express.text({ type: '*/*', limit: '256kb' }), (req, res) => {
  const rawBody = typeof req.body === 'string' ? req.body : '';
  if (/<!ENTITY/i.test(rawBody)) {
    const m = /<!ENTITY\s+\S+\s+SYSTEM\s+["']([^"']+)["']/i.exec(rawBody);
    if (m && /^https?:\/\//i.test(m[1])) fetch(m[1]).catch(() => {});
    res.writeHead(200, { 'Content-Type': 'application/xml' });
    return res.end('<root>ok</root>');
  }
  res.status(400).json({ error: 'expected an XML body' });
});

module.exports = router;
