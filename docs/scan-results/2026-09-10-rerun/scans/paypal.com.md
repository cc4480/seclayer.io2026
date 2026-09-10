# paypal.com

- Requested: `https://www.paypal.com`
- HTTP 200, 24.5s
- Score 93/100 — grade A
- 3 findings, 1 above Info

### Cookie "ts_c" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.paypal.com in this response header (cookie value redacted): "Set-Cookie: ts_c=<redacted>; Path=/; Domain=paypal.com; Expires=Sun, 09 Sep 2029 23:48:45 GMT; Secure". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 94 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

