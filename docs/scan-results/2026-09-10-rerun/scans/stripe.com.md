# stripe.com

- Requested: `https://stripe.com`
- HTTP 200, 13.3s
- Score 93/100 — grade A
- 4 findings, 1 above Info

### Cookie "cid" is set without the HttpOnly attribute

**Medium** · medium confidence · A05:2021 – Security Misconfiguration · IAST

```
Observed on https://stripe.com in this response header (cookie value redacted): "Set-Cookie: cid=<redacted>; Path=/; Domain=stripe.com; Max-Age=7776000; Secure; SameSite=Lax". A site may serve different cookie attributes to different clients, so a browser can show otherwise.
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

