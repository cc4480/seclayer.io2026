# vercel.com

- Requested: `https://vercel.com`
- HTTP 200, 30.3s
- Score 75/100 — grade C
- 7 findings, 4 above Info

### Cookie "_v-anonymous-id-renewed" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://vercel.com in this response header (cookie value redacted): "Set-Cookie: _v-anonymous-id-renewed=<redacted>; Path=/; Expires=Fri, 11 Sep 2026 23:43:07 GMT; Max-Age=86400; Domain=.vercel.com; Secure; SameSite=lax". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "_v-anonymous-id" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://vercel.com in this response header (cookie value redacted): "Set-Cookie: _v-anonymous-id=<redacted>; Path=/; Expires=Wed, 09 Dec 2026 23:43:07 GMT; Max-Age=7776000; Domain=.vercel.com; Secure; SameSite=lax". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### GraphiQL / GraphQL Playground Exposed

**Low** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Confirmed by fetching the path and matching the file's signature in the response body — not a status code alone.
```

### OpenAPI/Swagger Spec Exposed

**Low** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Confirmed by fetching the path and matching the file's signature in the response body — not a status code alone.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 4 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Verbose Server Framework Signature Leaked

**Info** · high confidence · A05:2021 – Security Misconfiguration · EASM

```
Informational scan-coverage context — not a detected vulnerability.
```

