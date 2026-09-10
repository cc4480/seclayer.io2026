# apple.com

- Requested: `https://www.apple.com`
- HTTP 200, 8.7s
- Score 85/100 — grade B
- 5 findings, 2 above Info

### Cookie "geo" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.apple.com in this response header (cookie value redacted): "Set-Cookie: geo=<redacted>; path=/; domain=.apple.com". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "geo" is set without the Secure attribute over HTTPS

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.apple.com in this response header (cookie value redacted): "Set-Cookie: geo=<redacted>; path=/; domain=.apple.com". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 9 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Verbose Server Framework Signature Leaked

**Info** · high confidence · A05:2021 – Security Misconfiguration · EASM

```
Informational scan-coverage context — not a detected vulnerability.
```

