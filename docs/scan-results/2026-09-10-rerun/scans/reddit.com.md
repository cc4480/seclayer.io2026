# reddit.com

- Requested: `https://www.reddit.com`
- HTTP 200, 10.2s
- Score 68/100 — grade D
- 7 findings, 4 above Info

### Cookie "edgebucket" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.reddit.com in this response header (cookie value redacted): "Set-Cookie: edgebucket=<redacted>; Domain=reddit.com; Max-Age=63071999; Path=/;  secure". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Kibana Instance Exposed

**Medium** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Confirmed by fetching the path and matching the file's signature in the response body — not a status code alone.
```

### GraphiQL / GraphQL Playground Exposed

**Low** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Confirmed by fetching the path and matching the file's signature in the response body — not a status code alone.
```

### Swagger UI Exposed

**Low** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Confirmed by fetching the path and matching the file's signature in the response body — not a status code alone.
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

