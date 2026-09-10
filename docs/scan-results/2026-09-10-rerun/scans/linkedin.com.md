# linkedin.com

- Requested: `https://www.linkedin.com`
- HTTP 200, 8.7s
- Score 85/100 — grade B
- 3 findings, 1 above Info

### Cookie "JSESSIONID" is set without the HttpOnly attribute

**Medium** · high confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.linkedin.com in this response header (cookie value redacted): "Set-Cookie: JSESSIONID=<redacted>; SameSite=None; Path=/; Domain=.www.linkedin.com; Secure". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 246 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

