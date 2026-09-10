# microsoft.com

- Requested: `https://www.microsoft.com`
- HTTP 200, 46.2s
- Score 60/100 — grade D
- 8 findings, 6 above Info

### Cookie "bStore" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.microsoft.com in this response header (cookie value redacted): "Set-Cookie: bStore=<redacted>; expires=Thu, 10-Sep-2026 23:47:10 GMT". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "bStore" is set without the Secure attribute over HTTPS

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.microsoft.com in this response header (cookie value redacted): "Set-Cookie: bStore=<redacted>; expires=Thu, 10-Sep-2026 23:47:10 GMT". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "CAS_PROGRAM" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.microsoft.com in this response header (cookie value redacted): "Set-Cookie: CAS_PROGRAM=<redacted>; expires=Thu, 10-Sep-2026 23:46:46 GMT; path=/; secure; SameSite=None". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Missing Content-Security-Policy (CSP)

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

### Missing X-Content-Type-Options (MIME Sniffing)

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

### Missing X-Frame-Options / Clickjacking Immunity

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (4 pages, 40 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

