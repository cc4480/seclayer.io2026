# cloudflare.com

- Requested: `https://www.cloudflare.com`
- HTTP 200, 13.6s
- Score 65/100 — grade D
- 7 findings, 5 above Info

### Cookie "kndctr_8AD56F28618A50850A495FB6_AdobeOrg_identity" is set without the HttpOnly attribute

**Medium** · high confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.cloudflare.com in this response header (cookie value redacted): "Set-Cookie: kndctr_8AD56F28618A50850A495FB6_AdobeOrg_identity=<redacted>; Expires=Sun, 10 Oct 2027 23:44:15 GMT; Path=/; Secure; SameSite=Lax". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Exposed JavaScript source map (/_connect/Globe.astro_astro_type_script_index_0_lang.C9vJTI-3.js.map)

**Low** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Confirmed by fetching the path and matching the file's signature in the response body — not a status code alone.
```

### Exposed JavaScript source map (/_connect/Hero.astro_astro_type_script_index_0_lang.BBNztvks.js.map)

**Low** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Confirmed by fetching the path and matching the file's signature in the response body — not a status code alone.
```

### Exposed JavaScript source map (/_connect/page.V2R8AmkL.js.map)

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

### Application Surface Mapped (10 pages, 0 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

