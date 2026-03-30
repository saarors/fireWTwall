# Middleware Pipeline

## Pipeline diagram

```
Request
  │
  ├─  0  Debug / Request ID        → assigns requestId, starts timer (debug mode only)
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

Log4Shell (stage 18) and Shellshock (stage 19) scan **every HTTP header** — not just well-known ones.

---

## Middleware detail

### Stage 0 — Debug / Request ID
**File:** `middleware/debug.js`
**Fires:** Always (no-op when `debug: false`)
**What it does:** Assigns a random hex `requestId` to `req.wafRequestId` and records `Date.now()` for processing-time calculation. In debug mode, attaches the timing finalizer that writes `X-WAF-Time`.
**HTTP status:** None (pass-through)

---

### Stage 1 — Security headers
**File:** `middleware/securityHeaders.js`
**Fires:** Every request
**What it does:** Adds 12 defensive response headers (HSTS, CSP, COOP, CORP, COEP, Referrer-Policy, Permissions-Policy, NEL, etc.) and removes `X-Powered-By`. Headers are set regardless of whether the request is eventually blocked.
**HTTP status:** None (headers added, pipeline continues)
**Severity levels used:** N/A

See [security-headers.md](../security-headers.md) for the full list.

---

### Stage 2 — Request size
**File:** `middleware/requestSize.js`
**Fires:** Every non-whitelisted request
**What it does:** Reads the `Content-Length` header and compares it to `maxBodySize`. Also hooks the raw `data` events to count streaming bytes against the limit.
**HTTP status:** `413 Request Entity Too Large`
**Severity levels used:** N/A

---

### Stage 3 — HTTP method filter
**File:** `middleware/methodFilter.js`
**Fires:** Every non-whitelisted request
**What it does:** Rejects TRACE, CONNECT, and any method not in `allowedMethods`.
**HTTP status:** `405 Method Not Allowed`
**Severity levels used:** N/A

---

### Stage 4 — IP filter
**File:** `middleware/ipFilter.js`
**Fires:** Every request
**What it does:** Checks the client IP (from socket or `X-Forwarded-For` if `trustedProxies` is set) against `whitelist` and `blacklist`. Whitelisted IPs set `req.wafTrusted = true` and skip all subsequent stages. Blacklisted IPs are immediately rejected.
**HTTP status:** `403 Forbidden` (blacklist)
**Severity levels used:** N/A

---

### Stage 5 — Rate limiting
**File:** `middleware/rateLimit.js`
**Fires:** Non-whitelisted requests
**What it does:** Sliding-window per-IP counter. Increments on each request; blocks when `maxRequests` is exceeded within `windowMs`. Blocked IPs remain blocked for `blockDurationMs`. Uses pluggable store (in-memory by default; swap with Redis via `setStore()`).
**HTTP status:** `429 Too Many Requests` + `Retry-After` header
**Severity levels used:** N/A

---

### Stage 6 — Bot detection
**File:** `middleware/botFilter.js`
**Fires:** Non-whitelisted requests
**What it does:** Matches `User-Agent` against 97 blocked signatures including sqlmap, nmap, ffuf, nuclei, Metasploit (msf/), tplmap, ysoserial, Shodan, and more.
**HTTP status:** `403 Forbidden`
**Severity levels used:** N/A

---

### Stage 7 — Prototype pollution
**File:** `middleware/prototypePollution.js`
**Fires:** Non-trusted requests
**What it does:** Scans query-string and body keys for `__proto__`, `constructor.prototype`, and similar patterns that could poison the JavaScript object prototype chain.
**HTTP status:** `403 Forbidden`
**Severity levels used:** `critical`

---

### Stage 8 — SSRF
**File:** `middleware/ssrf.js`
**Fires:** Non-trusted requests
**What it does:** Scans URL-suggestive params (`url`, `redirect`, `return`, `callback`, `next`, `dest`, `destination`, `src`, `source`, `uri`, `link`, `href`, `proxy`, `forward`) in query string and body. Also scans all header values. Detects private IP ranges, cloud metadata endpoints, and dangerous URI schemes.
**HTTP status:** `403 Forbidden`
**Severity levels used:** `critical`
**Rules:** `ssrf-private-ip`, `ssrf-cloud-metadata`, `ssrf-scheme`

---

### Stage 9 — XXE
**File:** `middleware/xxe.js`
**Fires:** Non-trusted requests with XML content type or XML body
**What it does:** Scans raw XML body strings for DOCTYPE declarations, external entity definitions, XInclude directives, and SYSTEM/PUBLIC identifiers. Skips non-XML requests entirely.
**HTTP status:** `403 Forbidden`
**Severity levels used:** `critical`
**Rules:** 6 rules (see [rules/xxe.md](../rules/xxe.md))

---

### Stage 10 — Open redirect
**File:** `middleware/openRedirect.js`
**Fires:** Non-trusted requests
**What it does:** Checks the value of params named `redirect`, `return`, `next`, `dest`, `destination`, `url`, `callback`, `goto`, `returnUrl`, `returnTo`, `continue`, `forward`, `location`, `target`, `to` for absolute URLs (`http://`, `https://`) or protocol-relative URLs (`//`).
**HTTP status:** `403 Forbidden`
**Severity levels used:** `medium`

---

### Stage 11 — Header injection (CRLF)
**File:** `middleware/headerInjection.js`
**Fires:** Non-trusted requests
**What it does:** Scans all header values for carriage-return (`\r`) and linefeed (`\n`) characters that could be used to inject additional HTTP headers or split the HTTP response.
**HTTP status:** `400 Bad Request`
**Severity levels used:** `high`

---

### Stage 12 — Path traversal
**File:** `middleware/pathTraversal.js`
**Fires:** Non-trusted requests
**Scans:** `req.originalUrl` (path), `req.query`, `req.body`
**What it does:** 18 rules covering `../` sequences, URL-encoded variants (`%2e%2e`), Unicode overlong encodings, null bytes, PHP stream wrappers, and known sensitive file targets.
**HTTP status:** `403 Forbidden`
**Severity levels used:** `critical`, `high`

See [rules/path-traversal.md](../rules/path-traversal.md).

---

### Stage 13 — Command injection
**File:** `middleware/commandInjection.js`
**Fires:** Non-trusted requests
**Scans:** `req.query`, `req.body`, `req.path`, `req.cookies`
**What it does:** 18 rules covering shell pipes (`|cmd`), subshell syntax (`$()`), Windows cmd/PowerShell, language interpreter one-liners (Python/Ruby/Perl/PHP/Node), network tools (wget/curl/netcat), and enumeration commands.
**HTTP status:** `403 Forbidden`
**Severity levels used:** `critical`, `high`

See [rules/command-injection.md](../rules/command-injection.md).

---

### Stage 14 — SQL injection
**File:** `middleware/sqlInjection.js`
**Fires:** Non-trusted requests
**Scans:** `req.query`, `req.body`, `req.path`, `req.cookies`
**What it does:** 38 rules covering UNION SELECT, stacked queries, blind time-based injection (SLEEP/WAITFOR/pg_sleep), DBMS fingerprinting, error-based injection (EXTRACTVALUE/UPDATEXML/GTID_SUBSET/EXP), MSSQL-specific attacks, and boolean tautologies.
**HTTP status:** `403 Forbidden`
**Severity levels used:** `critical`, `high`, `medium`

See [rules/sql-injection.md](../rules/sql-injection.md).

---

### Stage 15 — XSS
**File:** `middleware/xss.js`
**Fires:** Non-trusted requests
**Scans:** `req.query`, `req.body`, `req.path`, `req.cookies`
**What it does:** 29 rules covering `<script>` tags, `javascript:` protocol, `on*=` event handlers, DOM sinks (`innerHTML`, `document.write`, `location.href`), AngularJS template injection (`{{}}`), data URIs, iframes, SVG, CSS `@import`, `-moz-binding`, meta refresh, `srcset`, and more.
**HTTP status:** `403 Forbidden`
**Severity levels used:** `critical`, `high`, `medium`

See [rules/xss.md](../rules/xss.md).

---

### Stage 16 — SSTI
**File:** `middleware/ssti.js`
**Fires:** Non-trusted requests
**Scans:** `req.query`, `req.body`, `req.path`, `req.cookies`
**What it does:** 18 rules covering Python/Jinja2 (`__class__`, `__mro__`, `__subclasses__`, `popen`), Twig `_self.env`, FreeMarker `Execute`, Velocity `$class`, Smarty `{php}`, Ruby ERB (`<%=`), Java EL/Spring (`${Runtime.exec}`), Struts2/OGNL (`%{#}`), Spring4Shell (`class.module.classLoader`), and Tornado (`{% import os %}`).
**HTTP status:** `403 Forbidden`
**Severity levels used:** `critical` (all rules)

See [rules/ssti.md](../rules/ssti.md).

---

### Stage 17 — RFI
**File:** `middleware/rfi.js`
**Fires:** Non-trusted requests, only when a URL-suggestive param name is present
**Scans:** `req.query`, `req.body` — only params named `page`, `file`, `include`, `require`, `template`, `view`, `document`, `folder`, `root`, `path`, `pg`, `style`, `pdf`, `layout`, `conf`, `config`, `inc`, `mod`, `module`, `load`, `show`
**What it does:** 6 rules detecting HTTP/FTP/SMB/UNC remote inclusion, `expect://` wrapper, data URI inclusion, and LFI log/proc poisoning vectors.
**HTTP status:** `403 Forbidden`
**Severity levels used:** `critical` (all rules)

See [rules/rfi.md](../rules/rfi.md).

---

### Stage 18 — Log4Shell
**File:** `middleware/log4shell.js`
**Fires:** Non-trusted requests
**Scans:** All header values (primary vector), `req.query`, `req.body`, `req.cookies`
**What it does:** 6 rules detecting `${jndi:}` lookups with LDAP/RMI/DNS/IIOP protocols and all obfuscation variants (`${lower:j}ndi`, `${upper:j}ndi`, `${::-j}`, nested expressions). Every header is scanned because attackers inject into User-Agent, X-Api-Version, X-Forwarded-For, and arbitrary custom headers.
**HTTP status:** `403 Forbidden`
**Severity levels used:** `critical` (all rules)

See [rules/log4shell.md](../rules/log4shell.md).

---

### Stage 19 — Shellshock
**File:** `middleware/shellshock.js`
**Fires:** Non-trusted requests
**Scans:** All header values (primary vector), `req.query`, `req.body`
**What it does:** 2 rules detecting the `() { :; };` bash function definition syntax. Every header is scanned because CGI environments export HTTP headers as environment variables, making any header a viable injection vector.
**HTTP status:** `403 Forbidden`
**Severity levels used:** `critical` (both rules)

See [rules/shellshock.md](../rules/shellshock.md).

---

### Stage 20 — NoSQL injection
**File:** `middleware/nosqlInjection.js`
**Fires:** Non-trusted requests
**Scans:** Raw query string (for bracket notation before qs parsing), `req.query`, `req.body`
**What it does:** 11 rules detecting MongoDB operator injection via JSON body (`{"$ne": null}`) and URL bracket notation (`?user[$ne]=1`). Covers `$ne`, `$gt`, `$lt`, `$gte`, `$lte`, `$where`, `$regex`, `$in`, `$or`, `$expr`, and blind `$where sleep()` injection.
**HTTP status:** `403 Forbidden`
**Severity levels used:** `critical`, `high`, `medium`

See [rules/nosql-injection.md](../rules/nosql-injection.md).

---

### Stage 21 — LDAP injection
**File:** `middleware/ldapInjection.js`
**Fires:** Non-trusted requests
**Scans:** `req.query`, `req.body`, `req.cookies`
**What it does:** 6 rules detecting LDAP filter bypass via wildcard injection, parenthesis injection (OR/AND filter manipulation), null-byte termination, uid wildcard, admin/password filter injection, and hex-encoded LDAP special characters.
**HTTP status:** `403 Forbidden`
**Severity levels used:** `critical`, `high`

See [rules/ldap-injection.md](../rules/ldap-injection.md).

---

### Stage 22 — Deserialization
**File:** `middleware/deserialization.js`
**Fires:** Non-trusted requests
**Scans:** `req.query`, `req.body`, `req.cookies`, `req.rawBody` (if set)
**What it does:** 7 rules detecting PHP serialized objects (`O:N:` format), PHP arrays, Java serialized streams (base64 `rO0AB` and hex `aced0005`), Python pickle protocol headers, base64-encoded pickle, and the node-serialize RCE gadget.
**HTTP status:** `403 Forbidden`
**Severity levels used:** `critical`, `high`

See [rules/deserialization.md](../rules/deserialization.md).
