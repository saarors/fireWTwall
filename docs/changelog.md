# Changelog

---

## v2.4.0

**Python (WSGI/Django/Flask) and ASP.NET Core (.NET 6+) runtimes added. Automated tests. CI/CD.**

### New runtimes

| Runtime | Entry point | Install |
|---------|-------------|---------|
| **Python** | WSGI middleware + Django + Flask integrations | `pip install firewtwall` *(coming soon)* |
| **ASP.NET Core** | `IMiddleware` — `app.UseFireWTWall()` | NuGet `FireWTWall.AspNetCore` *(coming soon)* |

All 17 detectors, rate limiting, DDoS protection, IP filter, and bot detection are fully ported to both runtimes. Same NDJSON log format as Node.js and PHP.

### Other changes

- `CONTRIBUTING.md` added to repo root
- `docs/aspnet/` — full ASP.NET (.aspx / Web Forms) documentation
- `docs/architecture.md` updated with 5-runtime comparison table
- `docs/false-positives.md` updated with per-runtime bypass examples
- GitHub Actions CI added (Node.js, PHP, Python, ASP.NET Core)
- `tests/` — shared attack payload suite + per-runtime test runners

---

## v2.3.2

**ASP.NET (.aspx / Web Forms) runtime added.**

- Full port of all 17 detectors to C# targeting .NET Framework 4.7.2+
- `WafHttpModule` — drop-in `IHttpModule` registered via `Web.config`
- `WafConfig` singleton configured in `Global.asax.cs Application_Start`
- `MemoryCache`-backed rate limiter and DDoS protection (replaces APCu)
- `docs/aspnet/` — installation, configuration, and debug-mode guides

---

## v2.1.2

**PSR-4 autoloading fix; Packagist published.**

- Fixed `composer.json` PSR-4 autoload paths to correctly map `FireWTWall\\` to `php/src/` and `FireWTWall\\Detectors\\` to `php/src/detectors/`
- Published PHP package to Packagist as `saarors/firewtwall-php`
- Package is now installable via `composer require saarors/firewtwall-php`

---

## v2.1.1

**composer.json moved to repo root.**

- Moved `composer.json` from `php/` to the repository root to comply with Packagist requirements (Packagist reads `composer.json` from the root)
- No functional changes to WAF logic

---

## v2.1.0

**Metasploit-class protections: 7 new attack categories, 56 new rules.**

### New detection categories

| Category | Rules | Coverage |
|----------|:-----:|---------|
| SSTI | 18 | Jinja2, Twig, FreeMarker, Velocity, Smarty, ERB, OGNL/Struts2, Spring4Shell (CVE-2022-22965), Tornado |
| RFI | 6 | HTTP/FTP/SMB/expect:// inclusion, data URI, log poisoning, `/proc/self/environ` |
| Log4Shell | 6 | CVE-2021-44228 — JNDI LDAP/RMI/DNS + all obfuscation variants (`${lower:}`, `${upper:}`, `${::-j}`, nested) |
| Shellshock | 2 | CVE-2014-6271 / CVE-2014-7169 — `() { :; };` in any HTTP header |
| NoSQL injection | 11 | MongoDB `$ne`, `$gt`, `$lt`, `$gte`, `$lte`, `$where`, `$regex`, `$in`, `$or`, `$expr`, bracket-notation |
| LDAP injection | 6 | Filter bypass, parenthesis injection, null-byte, uid wildcard, admin filter, hex-encoded chars |
| Deserialization | 7 | PHP `O:N:` objects, Java `AC ED 00 05` (base64 + hex), Python pickle, node-serialize RCE |

### Bot list expansion

Added 20+ new blocked signatures including: `msf/`, `msfpayload`, `tplmap`, `ysoserial`, `jexboss`, `commix`, `dotdotpwn`, `xsser`, `beef-`. Total blocked bot signatures: **97**.

---

## v2.0.0

**Major upgrade: 4 new detectors, +40 rules, TypeScript types, cookie scanning, hardened security headers.**

### New detection categories

| Category | Rules |
|----------|:-----:|
| SSRF | 3 (private IPs, cloud metadata, dangerous URI schemes) |
| XXE | 6 (DOCTYPE, ENTITY SYSTEM/PUBLIC, parameter entities, XInclude) |
| Open Redirect | 1 (absolute URL or `//` in redirect-style params) |
| Prototype Pollution | 1 (`__proto__`, `constructor.prototype`) |
| Mass Assignment | — |

### Rule count increases

| Category | v1.x | v2.0.0 |
|----------|-----:|-------:|
| SQL injection | 28 | 38 |
| XSS | 21 | 29 |
| Path traversal | 14 | 18 |
| Command injection | 10 | 18 |

### New features

- **TypeScript** — `index.d.ts` bundled with the npm package. Exports: `WAFOptions`, `StoreAdapter`, `RateLimitOptions`.
- **Cookie scanning** — All pattern-based detectors now scan `req.cookies` in addition to query, body, and path.
- **Security header hardening** — Added COOP, CORP, COEP, NEL, `X-Permitted-Cross-Domain-Policies`. Updated Permissions-Policy to include `interest-cohort=()`.

---

## v1.0.0

**Initial release.**

### Detection categories

- SQL injection (28 rules)
- XSS (21 rules)
- Path traversal (14 rules)
- Command injection (10 rules)

### Infrastructure

- Rate limiting with sliding window algorithm
- IP filter with CIDR support (IPv4 + IPv6)
- Bad bot blocking (initially ~50 signatures)
- HTTP method filter
- Request size limit
- Security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- `X-Powered-By` removal
- NDJSON logging
- `waf-log` CLI viewer
- Pluggable Redis store via `setStore()`
- Node.js npm package (`firewtwall`)
- PHP auto-prepend file with APCu / file-based rate limiting
- `mode: 'log-only'` audit mode
