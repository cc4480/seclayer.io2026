# github.com

- Requested: `https://github.com`
- HTTP 200, 8.6s
- Score 73/100 — grade C
- 6 findings, 3 above Info

### Cookie "_octo" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://github.com in this response header (cookie value redacted): "Set-Cookie: _octo=<redacted>; expires=Fri, 10 Sep 2027 23:41:36 GMT; domain=.github.com; path=/; secure; SameSite=Lax". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### phpMyAdmin Panel Exposed

**Medium** · high confidence · A01:2021 – Broken Access Control · DAST

```
Confirmed by fetching the path and matching the file's signature in the response body — not a status code alone.
```

### GraphiQL / GraphQL Playground Exposed

**Low** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Confirmed by fetching the path and matching the file's signature in the response body — not a status code alone.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 47 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Verbose Server Framework Signature Leaked

**Info** · high confidence · A05:2021 – Security Misconfiguration · EASM

```
Informational scan-coverage context — not a detected vulnerability.
```

