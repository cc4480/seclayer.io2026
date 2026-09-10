# amazon.co.uk

- Requested: `https://www.amazon.co.uk`
- HTTP 200, 14.2s
- Score 40/100 — grade F
- 9 findings, 6 above Info

### Cookie "i18n-prefs" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.amazon.co.uk in this response header (cookie value redacted): "Set-Cookie: i18n-prefs=<redacted>; Domain=.amazon.co.uk; Expires=Fri, 10-Sep-2027 23:43:37 GMT; Path=/". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "i18n-prefs" is set without the Secure attribute over HTTPS

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.amazon.co.uk in this response header (cookie value redacted): "Set-Cookie: i18n-prefs=<redacted>; Domain=.amazon.co.uk; Expires=Fri, 10-Sep-2027 23:43:37 GMT; Path=/". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "lc-acbuk" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.amazon.co.uk in this response header (cookie value redacted): "Set-Cookie: lc-acbuk=<redacted>; Domain=.amazon.co.uk; Expires=Fri, 10-Sep-2027 23:43:37 GMT; Path=/". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "lc-acbuk" is set without the Secure attribute over HTTPS

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.amazon.co.uk in this response header (cookie value redacted): "Set-Cookie: lc-acbuk=<redacted>; Domain=.amazon.co.uk; Expires=Fri, 10-Sep-2027 23:43:37 GMT; Path=/". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "session-id-time" is set without the HttpOnly attribute

**Medium** · high confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.amazon.co.uk in this response header (cookie value redacted): "Set-Cookie: session-id-time=<redacted>; Domain=.amazon.co.uk; Expires=Fri, 10-Sep-2027 23:43:37 GMT; Path=/; Secure". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "session-id" is set without the HttpOnly attribute

**Medium** · high confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.amazon.co.uk in this response header (cookie value redacted): "Set-Cookie: session-id=<redacted>; Domain=.amazon.co.uk; Expires=Fri, 10-Sep-2027 23:43:37 GMT; Path=/; Secure". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 231 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Verbose Server Framework Signature Leaked

**Info** · high confidence · A05:2021 – Security Misconfiguration · EASM

```
Informational scan-coverage context — not a detected vulnerability.
```

