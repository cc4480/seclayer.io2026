# zoom.us

- Requested: `https://zoom.us`
- HTTP 200, 7.7s
- Score 60/100 — grade D
- 8 findings, 6 above Info

### Cookie "_zm_billing_visitor_guid" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://zoom.us in this response header (cookie value redacted): "Set-Cookie: _zm_billing_visitor_guid=<redacted>; Domain=zoom.us; Path=/; Secure". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "_zm_mtk_guid" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://zoom.us in this response header (cookie value redacted): "Set-Cookie: _zm_mtk_guid=<redacted>; Expires=Sat, 09 Sep 2028 23:49:59 GMT; Max-Age=63072000; Domain=zoom.us; Path=/; Secure". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "_zm_visitor_guid" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://zoom.us in this response header (cookie value redacted): "Set-Cookie: _zm_visitor_guid=<redacted>; Expires=Fri, 10 Sep 2027 23:49:59 GMT; Max-Age=31536000; Domain=zoom.us; Path=/; Secure". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
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

### Application Surface Mapped (10 pages, 1 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

