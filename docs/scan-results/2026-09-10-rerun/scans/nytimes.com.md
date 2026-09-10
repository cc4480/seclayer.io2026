# nytimes.com

- Requested: `https://www.nytimes.com`
- HTTP 200, 25.7s
- Score 48/100 — grade F
- 9 findings, 6 above Info

### Cookie "nyt-a" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.nytimes.com in this response header (cookie value redacted): "Set-Cookie: nyt-a=<redacted>; Expires=Fri, 10 Sep 2027 23:48:19 GMT; Path=/; Domain=.nytimes.com; SameSite=none; Secure". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "nyt-gdpr" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.nytimes.com in this response header (cookie value redacted): "Set-Cookie: nyt-gdpr=<redacted>; Expires=Fri, 11 Sep 2026 05:48:19 GMT; Path=/; Domain=.nytimes.com". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "nyt-gdpr" is set without the Secure attribute over HTTPS

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.nytimes.com in this response header (cookie value redacted): "Set-Cookie: nyt-gdpr=<redacted>; Expires=Fri, 11 Sep 2026 05:48:19 GMT; Path=/; Domain=.nytimes.com". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "nyt-geo" is set without the Secure attribute over HTTPS

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.nytimes.com in this response header (cookie value redacted): "Set-Cookie: nyt-geo=<redacted>; Expires=Fri, 11 Sep 2026 05:48:19 GMT; Path=/; Domain=.nytimes.com". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "nyt-purr" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.nytimes.com in this response header (cookie value redacted): "Set-Cookie: nyt-purr=<redacted>; Expires=Fri, 10 Sep 2027 23:48:19 GMT; Path=/; Domain=.nytimes.com; SameSite=Lax; Secure". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Kibana Instance Exposed

**Medium** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Confirmed by fetching the path and matching the file's signature in the response body — not a status code alone.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 6 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Verbose Server Framework Signature Leaked

**Info** · high confidence · A05:2021 – Security Misconfiguration · EASM

```
Informational scan-coverage context — not a detected vulnerability.
```

