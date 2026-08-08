// T1-XSS-Stored-001 — POST /api/comments persists `text` verbatim; GET
// /post/:id renders every stored comment back UNESCAPED, so a payload
// submitted once executes for every later visitor.
//
// T1-NC-001 (negative control) — the parallel /post-safe/:id thread stores
// and renders through he.encode(), so the identical payload is neutralized.
// Submitting the same script tag to both threads and comparing the two
// GET responses is what proves Seclayer isn't just pattern-matching the
// payload text, but actually checking whether it executes.
const express = require('express');
const he = require('he');
const db = require('../db');

const router = express.Router();

router.post('/api/comments', (req, res) => {
  const { text } = req.body || {};
  // postId defaults to 1 when the field is absent — a raw crawler-driven form
  // fuzzer resubmits exactly the fields it found on the page (the visible
  // "text" field), not any JS the page happens to run on submit, so the
  // vulnerable path must tolerate a bare `text=<payload>` POST, not just the
  // JS-mediated submission this page's own form also supports below.
  const postId = Number(req.body?.postId) || 1;
  if (typeof text !== 'string') return res.status(400).json({ error: 'text required' });
  db.prepare('INSERT INTO comments (post_id, text) VALUES (?, ?)').run(postId, text);
  res.status(201).json({ success: true });
});

router.get('/post/:id', (req, res) => {
  const comments = db.prepare('SELECT text FROM comments WHERE post_id = ?').all(req.params.id);
  let html = `<!doctype html><html><head><title>Post ${req.params.id}</title></head><body>` +
    `<h1>Post #${req.params.id}</h1>` +
    `<form method="POST" action="/api/comments" onsubmit="event.preventDefault();fetch('/api/comments',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({postId:${Number(req.params.id) || 1},text:document.getElementById('c').value})}).then(()=>location.reload());">` +
    `<input type="hidden" name="postId" value="${Number(req.params.id) || 1}">` +
    `<input id="c" name="text" placeholder="Leave a comment"><button type="submit">Post</button></form>` +
    `<div class="comments">`;
  for (const c of comments) html += `<p>${c.text}</p>`; // VULNERABLE: no escaping
  html += `</div><p><a href="/">Home</a></p></body></html>`;
  res.send(html);
});

router.post('/api/comments-safe', (req, res) => {
  const { text } = req.body || {};
  const postId = Number(req.body?.postId) || 1;
  if (typeof text !== 'string') return res.status(400).json({ error: 'text required' });
  db.prepare('INSERT INTO comments_safe (post_id, text) VALUES (?, ?)').run(postId, text);
  res.status(201).json({ success: true });
});

router.get('/post-safe/:id', (req, res) => {
  const comments = db.prepare('SELECT text FROM comments_safe WHERE post_id = ?').all(req.params.id);
  let html = `<!doctype html><html><head><title>Post ${req.params.id} (sanitized)</title></head><body>` +
    `<h1>Post #${req.params.id} — sanitized thread</h1>` +
    `<form method="POST" action="/api/comments-safe" onsubmit="event.preventDefault();fetch('/api/comments-safe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({postId:${Number(req.params.id) || 1},text:document.getElementById('cs').value})}).then(()=>location.reload());">` +
    `<input type="hidden" name="postId" value="${Number(req.params.id) || 1}">` +
    `<input id="cs" name="text" placeholder="Leave a comment"><button type="submit">Post</button></form>` +
    `<div class="comments">`;
  for (const c of comments) html += `<p>${he.encode(c.text)}</p>`; // SAFE: escaped
  html += `</div><p><a href="/">Home</a></p></body></html>`;
  res.send(html);
});

module.exports = router;
