# 🔥 fireWTwall

A production-ready **Web Application Firewall (WAF)** with zero external runtime dependencies, available in two drop-in versions:

| Version | Integration | Requirements |
|---------|-------------|-------------|
| **Node.js** | Express middleware | Node.js ≥ 16 |
| **PHP** | `auto_prepend_file` | PHP ≥ 8.0 |

Both versions share the same detection philosophy, rule sets, and NDJSON log format.

---

## Features

| Protection | Description |
|-----------|-------------|
| **SQL Injection** | 26 rules — UNION SELECT, stacked queries, time-based blind, DBMS fingerprinting, and more |
| **XSS** | 21 rules — script tags, event handlers, DOM manipulation, AngularJS templates, data URIs |
| **Path Traversal** | Dotdot sequences, null bytes, PHP stream wrappers, sensitive file detection |
| **Command Injection** | Shell pipes, subshells, Windows cmd/PowerShell, wget/curl RCE chains |
| **CRLF / Header Injection** | Response splitting, host-header injection |
| **Rate Limiting** | Sliding-window per IP — configurable window, limit, and block duration |
| **IP Filter** | Blacklist + whitelist with CIDR notation (IPv4 and IPv6) |
| **Bad Bot Blocking** | 40+ blocked signatures: sqlmap, nikto, masscan, dirbuster, Burp Suite, and more |
| **HTTP Method Filter** | Rejects non-configured methods (TRACE, CONNECT, custom verbs) |
| **Request Size Limit** | Content-Length header + streamed byte guard |
| **Security Headers** | X-Frame-Options, X-Content-Type-Options, COOP, CORP, Referrer-Policy, and more |

**Dual mode:** set `mode: 'reject'` to block, or `mode: 'log-only'` to audit without blocking (recommended for initial deployment).

---

## Node.js

### Install

```bash
cd nodejs
npm install   # only installs express for the example; waf.js itself has zero runtime deps
```

### Usage

```js
const express = require('express');
const { createWAF } = require('./waf');

const app = express();

// Parse body first so WAF can inspect it
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Mount the WAF — spread the returned middleware array
app.use(...createWAF({
  mode: 'reject',
  rateLimit: {
    windowMs: 60_000,    // 1-minute window
    maxRequests: 100,    // requests per window per IP
    blockDurationMs: 10 * 60_000,  // 10-minute block on violation
  },
  whitelist: ['127.0.0.1'],        // bypass all checks
  blacklist: ['203.0.113.0/24'],   // always block
  logPath: './logs/waf.log',
}));

app.get('/', (req, res) => res.json({ ok: true }));
app.listen(3000);
```

### Run the example server

```bash
cd nodejs
node example/server.js
```

Test it:
```bash
# SQL injection → 403
curl "http://localhost:3000/search?q=1+UNION+SELECT+*+FROM+users"

# XSS → 403
curl "http://localhost:3000/?q=<script>alert(1)</script>"

# Path traversal → 403
curl "http://localhost:3000/../../../etc/passwd"

# Command injection → 403
curl "http://localhost:3000/?cmd=|cat+/etc/passwd"

# Clean request → 200
curl "http://localhost:3000/"
```

### Configuration (`config/waf.config.js`)

| Key | Default | Description |
|-----|---------|-------------|
| `mode` | `'reject'` | `'reject'` blocks requests; `'log-only'` logs but passes |
| `allowedMethods` | `['GET','POST',...]` | Permitted HTTP methods |
| `maxBodySize` | `10485760` (10 MB) | Max Content-Length in bytes |
| `rateLimit.windowMs` | `60000` | Sliding-window duration in ms |
| `rateLimit.maxRequests` | `100` | Max requests per window per IP |
| `rateLimit.blockDurationMs` | `600000` | Block duration after violation |
| `whitelist` | `[]` | IPs/CIDRs that bypass all checks |
| `blacklist` | `[]` | IPs/CIDRs that are always blocked |
| `bypassPaths` | `['/health','/ping']` | Paths that skip all WAF checks |
| `trustedProxies` | `[]` | Enable `X-Forwarded-For` parsing |
| `logPath` | `'./logs/waf.log'` | NDJSON log file path |
| `responseType` | `'json'` | Block response format: `'json'` or `'html'` |

### Using a Redis store (multi-process deployments)

```js
const { setStore } = require('./middleware/rateLimit');

setStore({
  get: (key)        => redisClient.get(key).then(JSON.parse),
  set: (key, value) => redisClient.set(key, JSON.stringify(value)),
  del: (key)        => redisClient.del(key),
});
```

---

## PHP

### Requirements

- PHP ≥ 8.0
- APCu extension (optional — highly recommended for production; file-based fallback is included)

### Installation

**Option A — `auto_prepend_file` in `php.ini`** (global, affects all PHP scripts):
```ini
auto_prepend_file = /absolute/path/to/fireWTwall/php/waf.php
```

**Option B — `.htaccess`** (per-directory, Apache only):
```apache
php_value auto_prepend_file "/absolute/path/to/fireWTwall/php/waf.php"
```

**Option C — manual include** (any PHP framework):
```php
<?php
require_once '/path/to/fireWTwall/php/waf.php';
// Your application code here
```

### Configuration (`config/waf.config.php`)

```php
return [
    'allowed_methods'   => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
    'max_body_size'     => 10 * 1024 * 1024,   // 10 MB
    'rate_limit'        => [
        'window_sec'         => 60,
        'max_requests'       => 100,
        'block_duration_sec' => 600,
    ],
    'whitelist'         => [],                   // IPs/CIDRs
    'blacklist'         => [],
    'bypass_paths'      => ['/health', '/ping'],
    'trusted_proxies'   => [],
    'mode'              => 'reject',             // 'reject' or 'log-only'
    'log_path'          => __DIR__ . '/../logs/waf.log',
    'response_type'     => 'json',               // 'json' or 'html'
];
```

### Rate limiter storage

- **APCu** (default when available): fast, atomic, shared across PHP-FPM workers.
- **File-based fallback**: uses `sys_get_temp_dir()`, safe for shared hosting. Slightly slower.

Enable APCu in `php.ini`:
```ini
extension=apcu
apc.enabled=1
```

---

## Log format

Every blocked request appends one JSON line to the log file:

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

**Severity levels:** `critical`, `high`, `medium`

**Sources:** `query`, `body`, `path`, `cookies`, `user-agent`, `header:<name>`

Log rotation is handled externally — use `logrotate` on Linux or Windows Task Scheduler.

---

## Security headers added to every response

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `SAMEORIGIN` |
| `X-XSS-Protection` | `1; mode=block` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` (Node.js) |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `Cache-Control` | `no-store` (PHP block responses only) |

---

## Project structure

```
fireWTwall/
├── nodejs/
│   ├── waf.js                   ← Entry: createWAF(options)
│   ├── package.json
│   ├── config/
│   │   ├── waf.config.js        ← All settings
│   │   └── bad-bots.json        ← Bot signatures
│   ├── middleware/              ← 11 independent middleware modules
│   │   ├── securityHeaders.js
│   │   ├── requestSize.js
│   │   ├── methodFilter.js
│   │   ├── ipFilter.js
│   │   ├── rateLimit.js         ← Pluggable store (swap for Redis)
│   │   ├── botFilter.js
│   │   ├── headerInjection.js
│   │   ├── pathTraversal.js
│   │   ├── commandInjection.js
│   │   ├── sqlInjection.js
│   │   └── xss.js
│   ├── utils/
│   │   ├── patternMatcher.js    ← Multi-pass URL/HTML decode engine
│   │   ├── ipUtils.js           ← IPv4 + IPv6 CIDR matching
│   │   └── logger.js            ← Buffered NDJSON logger
│   └── example/
│       └── server.js
│
└── php/
    ├── waf.php                  ← Entry point (auto_prepend_file target)
    ├── composer.json
    ├── config/
    │   ├── waf.config.php
    │   └── bad-bots.php
    └── src/
        ├── WAF.php              ← Pipeline orchestrator
        ├── Request.php          ← Normalised request + multi-pass decode
        ├── IpFilter.php         ← CIDR support for IPv4 + IPv6
        ├── RateLimiter.php      ← APCu or file-based fallback
        ├── Logger.php           ← NDJSON with flock
        ├── Response.php         ← Block responses + security headers
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

- **Start with `log-only` mode** in production. Review the logs for false positives before switching to `reject`.
- The **log directory** (`logs/`) must be writable by the web server but **not web-accessible**. The included `php/logs/.htaccess` handles this for Apache. Add a `location` block to your Nginx config accordingly.
- This WAF is a **defence-in-depth layer** — it does not replace input validation, parameterised queries, or proper output encoding in your application code.
- For high-traffic Node.js deployments with multiple processes/workers, replace the in-memory rate-limit store with Redis (see the Redis store example above).

---

## License

MIT
