# wikipedia.org

- Requested: `https://www.wikipedia.org`
- HTTP 200, 5.0s
- Score 63/100 — grade D
- 8 findings, 5 above Info

### Cookie "GeoIP" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.wikipedia.org in this response header (cookie value redacted): "Set-Cookie: GeoIP=<redacted>; Path=/; secure; Domain=.wikipedia.org". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "NetworkProbeLimit" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.wikipedia.org in this response header (cookie value redacted): "Set-Cookie: NetworkProbeLimit=<redacted>;Path=/;Secure;SameSite=None;Max-Age=3600". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
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

### Application Surface Mapped (1 pages, 1 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Verbose Server Framework Signature Leaked

**Info** · high confidence · A05:2021 – Security Misconfiguration · EASM

```
Informational scan-coverage context — not a detected vulnerability.
```

