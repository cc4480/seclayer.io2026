# apnews.com

- Requested: `https://apnews.com`
- HTTP 200, 7.6s
- Score 78/100 — grade C
- 6 findings, 3 above Info

### Cookie "kameleoonVisitorCode" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://apnews.com in this response header (cookie value redacted): "Set-Cookie: kameleoonVisitorCode=<redacted>; Max-Age=31536000; Path=/". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "kameleoonVisitorCode" is set without the Secure attribute over HTTPS

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://apnews.com in this response header (cookie value redacted): "Set-Cookie: kameleoonVisitorCode=<redacted>; Max-Age=31536000; Path=/". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Missing X-Content-Type-Options (MIME Sniffing)

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 3 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Verbose Server Framework Signature Leaked

**Info** · high confidence · A05:2021 – Security Misconfiguration · EASM

```
Informational scan-coverage context — not a detected vulnerability.
```

