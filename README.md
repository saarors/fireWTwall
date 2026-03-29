# 🔥 fireWTwall

[![npm](https://img.shields.io/npm/v/firewtwall)](https://www.npmjs.com/package/firewtwall)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D16-brightgreen)](https://nodejs.org)
[![PHP](https://img.shields.io/badge/php-%3E%3D8.0-777BB4)](https://www.php.net)

A production-ready **Web Application Firewall (WAF)** with **zero external runtime dependencies**, available as an **npm package** for Node.js/Express and as a drop-in **PHP auto-prepend file**.

| Version | Integration | Install |
|---------|-------------|---------|
| **Node.js** | Express middleware | `npm install firewtwall` |
| **PHP** | `auto_prepend_file` | Clone / download `php/` |

Both versions share the same detection philosophy, rule sets, and NDJSON log format.

---

## Protections

| Layer | What it catches |
|-------|----------------|
| **SQL Injection** | UNION SELECT, stacked queries, time-based blind (SLEEP/WAITFOR/pg_sleep), DBMS fingerprinting, BULK INSERT, OPENROWSET — 26 rules |
| **XSS** | Script tags, event handlers (`on*=`), DOM manipulation, AngularJS `{{}}` templates, data URIs, innerHTML — 21 rules |
| **Path Traversal** | `../` sequences, null bytes, PHP stream wrappers (`php://filter`), sensitive file detection (`.env`, `wp-config.php`, `.git/`) |
| **Command Injection** | Shell pipes/subshells, Windows cmd/PowerShell, wget/curl RCE chains, base64 decode |
| **CRLF / Header Injection** | HTTP response splitting, host-header injection |
| **Rate Limiting** | Sliding-window per IP — configurable window, limit, and block duration. Pluggable store (Redis-ready) |
| **IP Filter** | Blacklist + whitelist with CIDR notation — IPv4 and IPv6 |
| **Bad Bot Blocking** | 40+ blocked signatures: sqlmap, nikto, masscan, dirbuster, Burp Suite, and more |
| **HTTP Method Filter** | Rejects non-configured methods (TRACE, CONNECT, custom verbs) |
| **Request Size Limit** | Content-Length header check + streamed byte guard |
| **Security Headers** | X-Frame-Options, X-Content-Type-Options, COOP, CORP, Referrer-Policy on every response |

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
│   ├── package.json
│   ├── config/
│   │   ├── waf.config.js
│   │   └── bad-bots.json
│   ├── middleware/                ← 11 independent middleware modules
│   │   ├── securityHeaders.js
│   │   ├── requestSize.js
│   │   ├── methodFilter.js
│   │   ├── ipFilter.js
│   │   ├── rateLimit.js           ← Pluggable store interface
│   │   ├── botFilter.js
│   │   ├── headerInjection.js
│   │   ├── pathTraversal.js
│   │   ├── commandInjection.js
│   │   ├── sqlInjection.js
│   │   └── xss.js
│   └── utils/
│       ├── patternMatcher.js      ← Multi-pass URL/HTML decode engine
│       ├── ipUtils.js             ← IPv4 + IPv6 CIDR matching
│       └── logger.js              ← Buffered NDJSON logger
│
└── php/                           ← Drop-in PHP WAF
    ├── waf.php                    ← Entry point (auto_prepend_file target)
    ├── composer.json
    ├── config/
    │   ├── waf.config.php
    │   └── bad-bots.php
    └── src/
        ├── WAF.php
        ├── Request.php
        ├── IpFilter.php
        ├── RateLimiter.php
        ├── Logger.php
        ├── Response.php
        └── detectors/
            ├── SqlInjectionDetector.php
            ├── XssDetector.php
            ├── PathTraversalDetector.php
            ├── CommandInjectionDetector.php
            ├── HeaderInjectionDetector.php
            └── BotDetector.php
```

---

## Important notes

- **Start with `log-only` mode** in production. Review logs for false positives before enabling `reject`.
- The **`logs/` directory** must be writable by the web server but not web-accessible. The included `php/logs/.htaccess` handles this for Apache.
- This WAF is a **defence-in-depth layer** — it does not replace parameterised queries, input validation, or proper output encoding in your application.
- For multi-process Node.js deployments, replace the in-memory rate-limit store with Redis (see the Redis example above).

---

## License

MIT
