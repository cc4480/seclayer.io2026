# fastly.com

- Requested: `https://www.fastly.com`
- HTTP 200, 16.8s
- Score 73/100 — grade C
- 7 findings, 4 above Info

### Cookie "_fs_ch_st_FSBmUei20MqUiJb9" is set without the Secure attribute over HTTPS

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.fastly.com in this response header (cookie value redacted): "Set-Cookie: _fs_ch_st_FSBmUei20MqUiJb9=<redacted>; Max-Age=10; HttpOnly; Path=/". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "ff_revamp" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.fastly.com in this response header (cookie value redacted): "Set-Cookie: ff_revamp=<redacted>; domain=.fastly.com; path=/; max-age=2592000; SameSite=Lax; Secure". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Missing Content-Security-Policy (CSP)

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed directly from the response headers and cookie attributes on the scanned URL.
```

### Exposed JavaScript source map (/_astro/page.sxlF4EnU.js.map)

**Low** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Confirmed by fetching the path and matching the file's signature in the response body — not a status code alone.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 5 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Verbose Server Framework Signature Leaked

**Info** · high confidence · A05:2021 – Security Misconfiguration · EASM

```
Informational scan-coverage context — not a detected vulnerability.
```

