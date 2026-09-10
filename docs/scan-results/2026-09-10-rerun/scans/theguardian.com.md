# theguardian.com

- Requested: `https://www.theguardian.com`
- HTTP 200, 10.8s
- Score 70/100 — grade C
- 6 findings, 4 above Info

### Cookie "gu_client_ab_tests" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.theguardian.com in this response header (cookie value redacted): "Set-Cookie: gu_client_ab_tests=<redacted>; path=/; max-age=2592000; domain=.theguardian.com; Secure". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "gu_client_ab_tests" is set without the Secure attribute over HTTPS

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.theguardian.com in this response header (cookie value redacted): "Set-Cookie: gu_client_ab_tests=<redacted>; path=/; max-age=0". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "gu_v2_mvt_id" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.theguardian.com in this response header (cookie value redacted): "Set-Cookie: gu_v2_mvt_id=<redacted>; path=/; max-age=7776000; domain=.theguardian.com; Secure". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Cookie "gu_v2_mvt_id" is set without the Secure attribute over HTTPS

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://www.theguardian.com in this response header (cookie value redacted): "Set-Cookie: gu_v2_mvt_id=<redacted>; path=/; max-age=0". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
```

### Active Exploit Probing Skipped (Unverified Target)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

### Application Surface Mapped (10 pages, 7 endpoints)

**Info** · high confidence · A05:2021 – Security Misconfiguration · DAST

```
Informational scan-coverage context — not a detected vulnerability.
```

