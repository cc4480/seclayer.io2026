// T1-XSS-Reflected-001 — GET /profile?name= echoes `name` straight into the
// HTML template with no escaping.
const express = require('express');

const router = express.Router();

router.get('/profile', (req, res) => {
  const name = req.query.name || 'Guest';
  res.send(
    `<!doctype html><html><head><title>Profile</title></head><body>` +
      `<h1>Welcome ${name}</h1>` +
      `<p><a href="/">Home</a></p>` +
      `</body></html>`
  );
});

module.exports = router;
