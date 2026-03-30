# 🔥 fireWTwall

[![npm](https://img.shields.io/npm/v/firewtwall)](https://www.npmjs.com/package/firewtwall)
[![npm version](https://img.shields.io/badge/version-2.0.0-orange)](https://www.npmjs.com/package/firewtwall)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D16-brightgreen)](https://nodejs.org)
[![PHP](https://img.shields.io/badge/php-%3E%3D8.0-777BB4)](https://www.php.net)
[![TypeScript](https://img.shields.io/badge/types-included-blue)](nodejs/index.d.ts)
[![Author](https://img.shields.io/badge/author-saarors-blue)](https://github.com/saarors)

> **Created and maintained by [saarors](https://github.com/saarors)**

A production-ready **Web Application Firewall (WAF)** with **zero external runtime dependencies**, available as an **npm package** for Node.js/Express and as a drop-in **PHP auto-prepend file**.

| Version | Integration | Install |
|---------|-------------|---------|
| **Node.js** | Express middleware | `npm install firewtwall` |
| **PHP** | `auto_prepend_file` | Clone / download `php/` |

Both versions share the same detection philosophy, rule sets, and NDJSON log format.

---

## What's new in v2.0.0

| Area | Change |
|------|--------|
| 🛡️ **SSRF detection** | Blocks private IPs, cloud metadata (169.254.169.254), dangerous URI schemes in redirect params |
| 🛡️ **XXE detection** | Catches DOCTYPE, ENTITY SYSTEM/PUBLIC, parameter entities, XInclude in XML bodies |
| 🛡️ **Open redirect** | Blocks absolute-URL values in redirect/return/next/dest params |
| 🛡️ **Prototype pollution** | Detects `__proto__`, `constructor.prototype`, recursive JSON key scanning (Node.js) |
| 🛡️ **Mass assignment** | PHP equivalent — blocks magic key names like `__destruct`, `__wakeup`, `_method` |
| 📋 **+40 new rules** | SQL (+12), XSS (+8), Command injection (+8), Path traversal (+4) |
| 🤖 **69 bad bots** | Added: ffuf, gobuster, nuclei, interactsh, Shodan, Censys, Metasploit, Nessus, wpscan, and 25 more |
| 🍪 **Cookie scanning** | All detectors now inspect cookies as a separate source |
| 🔒 **Security headers** | Added HSTS, CSP, `X-Permitted-Cross-Domain-Policies`, NEL, removes `X-Powered-By` |
| 📝 **TypeScript types** | Full `index.d.ts` included in the npm package |

---

## Protections

| Layer | What it catches | Rules |
|-------|----------------|-------|
| **SQL Injection** | UNION SELECT, stacked queries, blind (SLEEP/WAITFOR), DBMS fingerprinting, EXTRACTVALUE, UPDATEXML, GTID_SUBSET, EXP(~()), sys schema, CASE WHEN | **38** |
| **XSS** | Script tags, event handlers, DOM sinks, AngularJS templates, data URIs, SVG animate, CSS @import, -moz-binding, meta refresh | **29** |
| **Path Traversal** | `../` sequences, null bytes, PHP stream wrappers, Windows paths (`C:\`, system32), `/boot/grub`, `.env`, `.git/`, `.ssh/` | **18** |
| **Command Injection** | Shell pipes/subshells, PowerShell, wget/curl RCE, Python/Ruby/Perl/PHP/Node CLI, netcat, whoami, env dump | **18** |
| **SSRF** | Private IP ranges, cloud metadata endpoints, dangerous URI schemes (file://, gopher://) in URL params | **3** |
| **XXE** | DOCTYPE, ENTITY SYSTEM/PUBLIC, parameter entities, XInclude — XML bodies only | **5** |
| **Open Redirect** | Absolute URLs or `//` in redirect/return/next/dest params | **1** |
| **Prototype Pollution** | `__proto__`, `constructor.prototype` in query/body/JSON (Node.js); magic key names (PHP) | **1** |
| **CRLF / Header Injection** | HTTP response splitting, host-header injection | — |
| **Rate Limiting** | Sliding-window per IP — configurable window, limit, and block duration. Pluggable store (Redis-ready) | — |
| **IP Filter** | Blacklist + whitelist with CIDR notation — IPv4 and IPv6 | — |
| **Bad Bot Blocking** | 69 blocked signatures: sqlmap, nikto, nmap, ffuf, nuclei, Shodan, wpscan, Metasploit, and more | — |
| **HTTP Method Filter** | Rejects non-configured methods (TRACE, CONNECT, custom verbs) | — |
| **Request Size Limit** | Content-Length header check + streamed byte guard | — |
| **Security Headers** | HSTS, CSP, COOP, CORP, COEP, Referrer-Policy, Permissions-Policy, NEL, removes `X-Powered-By` | — |

**Dual mode:** `mode: 'reject'` blocks requests · `mode: 'log-only'` logs without blocking (recommended for initial rollout)

---

## Node.js — npm package

### Install

```bash
npm install firewtwall
```

### Quick start

```js
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

### With custom options

```js
const { createWAF, setStore } = require('firewtwall');

app.use(...createWAF({
  mode: 'reject',              // 'reject' | 'log-only'
  rateLimit: {
    windowMs: 60_000,          // 1-minute sliding window
    maxRequests: 100,          // requests allowed per window per IP
    blockDurationMs: 600_000,  // 10-minute block after violation
  },
  whitelist: ['127.0.0.1', '10.0.0.0/8'],  // bypass all checks
  blacklist: ['203.0.113.0/24'],            // always block
  bypassPaths: ['/health', '/metrics'],
  trustedProxies: ['172.16.0.1'],          // enable X-Forwarded-For
  logPath: './logs/waf.log',
  responseType: 'json',        // 'json' | 'html'
}));
```

### Debug mode

```js
app.use(...createWAF({ debug: true }));
```

When `debug: true` every request (pass **and** block) is fully traced:

| What changes | Detail |
|--------------|--------|
| **All requests logged** | Not just blocks — every request hits the NDJSON log with processing time |
| **Response headers** | Four `X-WAF-*` headers are injected (see table below) |
| **Log verbosity** | Matched value, decoded value, and the specific check that fired are included |

**Response headers added in debug mode:**

| Header | Example | Always? |
|--------|---------|---------|
| `X-WAF-RequestId` | `f47ac10b58cc1122` | ✅ |
| `X-WAF-Result` | `blocked` or `passed` | ✅ |
| `X-WAF-Rule` | `sql-union-select` | ❌ blocked only |
| `X-WAF-Time` | `0.831ms` | ✅ |

**Sample debug log entry (passed request):**
```json
{
  "timestamp": "2026-03-30T10:00:00Z",
  "requestId": "f47ac10b58cc1122",
  "ip": "127.0.0.1",
  "method": "GET",
  "path": "/",
  "result": "passed",
  "processingTimeMs": 0.42,
  "checksRun": 11
}
```

**Sample debug log entry (blocked request):**
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

**Debugging nmap scans:** nmap probes are caught by the **bot filter** (`nmap-scan` rule). To confirm in debug mode:
```bash
# Run nmap against your dev server
nmap -sV localhost -p 3000

# Tail the WAF log — you'll see the blocked probe
npx waf-log --blocked --rule nmap
```

> ⚠️ **Never enable `debug: true` in production** — it exposes internal rule names to the client via response headers.

### Log viewer CLI

After installing the package a `waf-log` binary is available:

```bash
# Last 50 entries (default)
npx waf-log

# Last 100 entries from a custom log file
npx waf-log --tail 100 ./logs/waf.log

# Stats summary — top rules, top IPs, severity breakdown
npx waf-log --stats

# Only blocked requests
npx waf-log --blocked

# Filter by IP or rule (partial match)
npx waf-log --ip 203.0.113.42
npx waf-log --rule sql

# Entries after a date
npx waf-log --since 2026-03-29T12:00:00Z

# Raw NDJSON output (pipe-friendly)
npx waf-log --json | jq .
```

### Swap the rate-limit store (Redis, multi-process deployments)

```js
const { createWAF, setStore } = require('firewtwall');
const redis = require('ioredis');

const client = new redis();

setStore({
  get: async (key)        => JSON.parse(await client.get(key)),
  set: async (key, value) => client.set(key, JSON.stringify(value)),
  del: async (key)        => client.del(key),
});

app.use(...createWAF());
```

### Configuration reference

| Key | Default | Description |
|-----|---------|-------------|
| `mode` | `'reject'` | `'reject'` blocks · `'log-only'` audits |
| `allowedMethods` | `['GET','POST','PUT','PATCH','DELETE','OPTIONS','HEAD']` | Permitted HTTP methods |
| `maxBodySize` | `10485760` | Max Content-Length in bytes (10 MB) |
| `rateLimit.windowMs` | `60000` | Sliding-window size in ms |
| `rateLimit.maxRequests` | `100` | Requests allowed per window per IP |
| `rateLimit.blockDurationMs` | `600000` | Block duration after violation |
| `whitelist` | `[]` | IPs / CIDRs that bypass all checks |
| `blacklist` | `[]` | IPs / CIDRs that are always blocked |
| `bypassPaths` | `['/health','/ping']` | Paths that skip all WAF checks |
| `trustedProxies` | `[]` | Enables `X-Forwarded-For` parsing |
| `logPath` | `'./logs/waf.log'` | NDJSON log file path |
| `responseType` | `'json'` | Block response format: `'json'` or `'html'` |

### Test it

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

# Clean request → 200
curl http://localhost:3000/
```

---

## PHP

### Requirements

- PHP ≥ 8.0
- APCu extension (optional — highly recommended; file-based fallback included)

### Installation

**Option A — `php.ini`** (global):
```ini
auto_prepend_file = /absolute/path/to/fireWTwall/php/waf.php
```

**Option B — `.htaccess`** (per-directory, Apache):
```apache
php_value auto_prepend_file "/absolute/path/to/fireWTwall/php/waf.php"
```

**Option C — manual include** (any framework):
```php
<?php
require_once '/path/to/fireWTwall/php/waf.php';
// Your application continues here
```

### Configuration (`php/config/waf.config.php`)

```php
return [
    'allowed_methods'   => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
    'max_body_size'     => 10 * 1024 * 1024,
    'rate_limit'        => [
        'window_sec'         => 60,
        'max_requests'       => 100,
        'block_duration_sec' => 600,
    ],
    'whitelist'         => [],
    'blacklist'         => [],
    'bypass_paths'      => ['/health', '/ping'],
    'trusted_proxies'   => [],
    'mode'              => 'reject',     // 'reject' or 'log-only'
    'log_path'          => __DIR__ . '/../logs/waf.log',
    'response_type'     => 'json',       // 'json' or 'html'
];
```

### Rate limiter storage

| Backend | When used | Notes |
|---------|-----------|-------|
| **APCu** | APCu extension loaded | Fast, atomic, shared across PHP-FPM workers |
| **File-based** | Fallback | Uses `sys_get_temp_dir()` — safe for shared hosting |

Enable APCu in `php.ini`:
```ini
extension=apcu
apc.enabled=1
```

---

## Log format

Every blocked request appends one NDJSON line to the log file:

```json
{
  "timestamp": "2026-03-29T15:30:00Z",
  "requestId": "f47ac10b58cc1122",
  "ip": "203.0.113.42",
  "method": "GET",
  "path": "/search",
  "rule": "sql-union-select",
  "matched": "UNION SELECT",
  "source": "query",
  "severity": "critical",
  "userAgent": "sqlmap/1.7"
}
```

**Severity levels:** `critical` · `high` · `medium`

**Sources:** `query` · `body` · `path` · `cookies` · `user-agent` · `header:<name>`

---

## Security headers (added to every response)

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `SAMEORIGIN` |
| `X-XSS-Protection` | `1; mode=block` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` |

---

## Project structure

```
fireWTwall/
├── nodejs/                        ← Published as npm package "firewtwall"
│   ├── waf.js                     ← Entry: createWAF(), setStore()
│   ├── index.d.ts                 ← TypeScript definitions (v2.0.0)
│   ├── package.json
│   ├── config/
│   │   ├── waf.config.js
│   │   └── bad-bots.json          ← 69 blocked signatures
│   ├── middleware/                ← 16 independent middleware modules
│   │   ├── securityHeaders.js     ← HSTS, CSP, NEL, removes X-Powered-By
│   │   ├── requestSize.js
│   │   ├── methodFilter.js
│   │   ├── ipFilter.js
│   │   ├── rateLimit.js           ← Pluggable store interface
│   │   ├── botFilter.js
│   │   ├── prototypePollution.js  ← NEW: __proto__, constructor.prototype
│   │   ├── ssrf.js                ← NEW: private IPs, cloud metadata, schemes
│   │   ├── xxe.js                 ← NEW: DOCTYPE, ENTITY, XInclude
│   │   ├── openRedirect.js        ← NEW: absolute URLs in redirect params
│   │   ├── headerInjection.js
│   │   ├── pathTraversal.js       ← 18 rules (+ Windows, system32, /boot)
│   │   ├── commandInjection.js    ← 18 rules (+ Python/Ruby/Perl/PHP/Node CLI)
│   │   ├── sqlInjection.js        ← 38 rules (+ EXTRACTVALUE, GTID, EXP(~()))
│   │   └── xss.js                 ← 29 rules (+ CSS @import, SVG animate)
│   └── utils/
│       ├── patternMatcher.js      ← Multi-pass decode + cookie scanning
│       ├── ipUtils.js             ← IPv4 + IPv6 CIDR matching
│       └── logger.js              ← Buffered NDJSON logger
│
└── php/                           ← Drop-in PHP WAF
    ├── waf.php                    ← Entry point (auto_prepend_file target)
    ├── composer.json
    ├── config/
    │   ├── waf.config.php
    │   └── bad-bots.php           ← 69 blocked signatures
    └── src/
        ├── WAF.php                ← 15-step pipeline
        ├── Request.php            ← Double-encoding + Unicode decode
        ├── IpFilter.php
        ├── RateLimiter.php
        ├── Logger.php
        ├── Response.php           ← HSTS, CSP, removes X-Powered-By
        └── detectors/
            ├── SqlInjectionDetector.php   ← 38 rules
            ├── XssDetector.php            ← 29 rules
            ├── PathTraversalDetector.php  ← 18 rules
            ├── CommandInjectionDetector.php ← 18 rules
            ├── HeaderInjectionDetector.php
            ├── BotDetector.php
            ├── SsrfDetector.php           ← NEW
            ├── XxeDetector.php            ← NEW
            ├── OpenRedirectDetector.php   ← NEW
            └── MassAssignmentDetector.php ← NEW
```

---

## Important notes

- **Start with `log-only` mode** in production. Review logs for false positives before enabling `reject`.
- The **`logs/` directory** must be writable by the web server but not web-accessible. The included `php/logs/.htaccess` handles this for Apache.
- This WAF is a **defence-in-depth layer** — it does not replace parameterised queries, input validation, or proper output encoding in your application.
- For multi-process Node.js deployments, replace the in-memory rate-limit store with Redis (see the Redis example above).

---

## License

MIT © [saarors](https://github.com/saarors)

---

## Credits

### Author & lead developer

| | |
|---|---|
| **[saarors](https://github.com/saarors)** | Created fireWTwall from scratch — designed the architecture, wrote the detection rules for both the Node.js and PHP versions, built the npm package, and shipped every release. |

### Contributors

| Contributor | Commits | Lines added | Lines removed |
|-------------|---------|-------------|---------------|
| **[saarors](https://github.com/saarors)** | 9 | +3,696 | -403 |
| claude (AI pair-programmer) | 6 | +3,473 | -201 |

> **saarors** holds the #1 contributor spot by commits, lines added, and lines removed.
> All design decisions, architecture choices, and release ownership belong to **saarors**.

[![GitHub](https://img.shields.io/badge/github-saarors%2FfireWTwall-181717?logo=github)](https://github.com/saarors/fireWTwall)
[![npm](https://img.shields.io/badge/npm-firewtwall-CB3837?logo=npm)](https://www.npmjs.com/package/firewtwall)
