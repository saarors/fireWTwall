# SSRF Rules

The WAF applies 3 SSRF rules.

**Scanned sources:** URL-suggestive query params and body fields, all header values.

---

## What SSRF is

Server-Side Request Forgery (SSRF) causes the server to make an outbound HTTP request to a URL controlled by the attacker. This is dangerous because:

- The server may have access to internal services not reachable from the internet (databases, admin panels, Redis, Elasticsearch)
- Cloud metadata endpoints expose credentials (AWS IAM role keys, GCP service account tokens)
- The attack bypasses network-level controls — the request originates from a trusted internal IP

---

## Which parameters trigger the SSRF check

Only parameters with URL-suggestive names are scanned:

| Parameter names checked |
|------------------------|
| `url`, `redirect`, `return`, `callback`, `next`, `dest`, `destination`, `src`, `source`, `uri`, `link`, `href`, `proxy`, `forward` |

These are checked in both `req.query` and `req.body`. All header values are also scanned (to catch SSRF via `Referer`, `Origin`, `X-Forwarded-*`).

---

## All 3 rules

### ssrf-private-ip

Detects private IP ranges and loopback addresses in URL values.

**Private ranges blocked:**
- `127.0.0.0/8` — loopback
- `10.0.0.0/8` — RFC 1918 private
- `172.16.0.0/12` — RFC 1918 private
- `192.168.0.0/16` — RFC 1918 private
- `0.0.0.0` — unspecified address
- `::1` — IPv6 loopback
- `fd00::/8` and `fc00::/7` — IPv6 unique local

```bash
# Internal admin panel
curl "http://localhost:3000/?redirect=http://192.168.1.1/admin"

# Localhost database
curl "http://localhost:3000/?url=http://127.0.0.1:6379"

# Internal Kubernetes service
curl "http://localhost:3000/?dest=http://10.0.0.1:8080/api"
```

---

### ssrf-cloud-metadata

Detects requests to cloud instance metadata endpoints. These endpoints are accessible only from within the cloud instance and return credentials, instance metadata, and configuration.

| Endpoint | Cloud provider |
|----------|---------------|
| `169.254.169.254` | AWS IMDSv1, GCP, Azure (link-local) |
| `metadata.google.internal` | Google Cloud Platform |
| `metadata.azure.com` | Microsoft Azure |
| `100.100.100.200` | Alibaba Cloud |

**AWS IMDSv1 attack:**
```bash
# Retrieve AWS IAM role credentials
curl "http://localhost:3000/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

**GCP metadata attack:**
```bash
curl "http://localhost:3000/?src=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

**Azure IMDS attack:**
```bash
curl "http://localhost:3000/?dest=http://169.254.169.254/metadata/instance?api-version=2021-02-01"
```

---

### ssrf-scheme

Detects dangerous URI schemes that should not appear in redirect/URL parameters.

| Scheme | Risk |
|--------|------|
| `file://` | Reads local files on the server |
| `gopher://` | Can reach internal TCP services, compose raw HTTP/SMTP/Redis requests |
| `dict://` | DICT protocol — can probe internal services |
| `ftp://` | FTP — can reach internal FTP servers |
| `ldap://` | LDAP — can reach internal LDAP directories |
| `tftp://` | TFTP — can reach internal TFTP servers |

```bash
# File read via SSRF
curl "http://localhost:3000/?url=file:///etc/passwd"

# Gopher protocol — attack internal Redis
curl "http://localhost:3000/?dest=gopher://127.0.0.1:6379/_FLUSHALL%0d%0a"
```

---

## Header scanning

SSRF can be injected into headers that the server might act on:

```bash
# Via Referer header
curl -H "Referer: http://192.168.1.1/admin" http://localhost:3000/

# Via Origin header
curl -H "Origin: http://169.254.169.254" http://localhost:3000/

# Via X-Forwarded-Host
curl -H "X-Forwarded-Host: metadata.google.internal" http://localhost:3000/
```

All header values pass through the SSRF detector regardless of their name.

---

## Log entry

```json
{
  "rule": "ssrf-cloud-metadata",
  "matched": "169.254.169.254",
  "source": "query:url",
  "severity": "critical"
}
```

The `source` field includes the parameter name (e.g., `query:url`, `body:redirect`, `header:referer`) so you can identify exactly which field carried the payload.
