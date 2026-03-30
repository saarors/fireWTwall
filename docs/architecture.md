# Architecture

## Request lifecycle

Every incoming request passes through up to 23 ordered stages. Early stages (IP filter, rate limit) operate on metadata and short-circuit before pattern matching. Pattern matching stages (12–22) apply multi-pass decode before testing regex patterns.

```
Request arrives
  │
  ├─ Stage 0:  Assign requestId + start timer (debug mode only)
  ├─ Stage 1:  Add security headers to response (always, even for blocked requests)
  ├─ Stage 2:  Check Content-Length vs maxBodySize → 413 if exceeded
  ├─ Stage 3:  Check HTTP method against allowedMethods → 405 if not allowed
  ├─ Stage 4:  IP filter
  │              Whitelisted? → set req.wafTrusted = true → skip stages 5-22
  │              Blacklisted? → 403
  ├─ Stage 5:  Rate limit (only if not wafTrusted) → 429 + Retry-After
  ├─ Stage 6:  Bot filter — User-Agent vs 97 signatures → 403
  ├─ Stage 7:  Prototype pollution — scan query/body keys → 403
  ├─ Stage 8:  SSRF — scan URL-like params + all headers → 403
  ├─ Stage 9:  XXE — scan raw XML body → 403
  ├─ Stage 10: Open redirect — scan redirect-like params → 403
  ├─ Stage 11: Header injection — scan all header values for CR/LF → 400
  ├─ Stages 12-22: Pattern-based detection (multi-pass decode + regex)
  │
  ▼
Application handler
```

Stages 12–22 all call `scanSources()` which internally calls `deepDecode()` on each value before testing patterns.

---

## How patternMatcher.js works

`utils/patternMatcher.js` provides two key functions:

### deepDecode(value)

Applies multi-pass normalization to detect payloads that are encoded to evade simple string matching:

1. **URL decode** — `%XX` sequences: `%3C` → `<`
2. **Double URL decode** — `%253C` → `%3C` → `<`
3. **HTML entity decode** — `&lt;` → `<`, `&#60;` → `<`, `&#x3c;` → `<`
4. **Overlong UTF-8** — Two-byte sequences like `%c0%ae` → `.` (path traversal)
5. **UTF-7 normalization** — `+ADw-` → `<` (legacy IE XSS vector)

The function applies multiple decode passes until the output stabilizes, catching nested encoding like `%2525` → `%25` → `%`.

### scanSources(sources, rules)

Iterates over an array of `{ label, data }` source objects. For each source, flattens the data (query object, body object, string) into individual string values and applies `deepDecode()` followed by each rule's regex pattern. Returns the first hit as `{ rule, matched, source }` or null.

Flattening handles:
- Flat objects: `{ key: 'value' }`
- Nested objects: `{ key: { nested: 'value' } }` (one level)
- Arrays: `{ key: ['a', 'b'] }`
- Raw strings: the path string, cookie values

Cookie scanning uses the `cookie:name` source label. Header scanning (Log4Shell, Shellshock, SSRF) uses the `header:name` label.

---

## How scanSources handles cookies

Cookies are passed as `req.cookies` (an object keyed by cookie name if `cookie-parser` is used) or parsed from the `Cookie` header string. The source label is `cookie:<name>` so blocked-request logs identify exactly which cookie carried the payload.

---

## How logging works

`utils/logger.js` maintains a write stream to the configured `logPath`. Each log entry is a single-line JSON object followed by a newline (NDJSON format). The write stream uses Node.js's built-in buffering — no synchronous I/O on the hot path.

**Node.js logger behavior:**
- Stream is created lazily on first write
- Each `logBlock()` call appends one line
- If the write stream encounters an error (disk full, permissions), it logs to `stderr` and continues

**PHP logger behavior:**
- `Logger.php` uses `fopen()` + `flock(LOCK_EX)` + `fwrite()` + `flock(LOCK_UN)` for each write
- `flock` prevents interleaved writes from concurrent PHP-FPM workers
- File is opened in append mode (`'a'`)

Both versions write the same NDJSON format. See [log-format.md](log-format.md) for the field reference.

---

## How rate limiting works

The rate limiter implements a **sliding window** algorithm:

1. The store key is `waf:rl:<ip>`.
2. On each request, fetch the current window record: `{ count, windowStart, resetAt }`.
3. If no record exists, or `Date.now() > resetAt`, create a new window.
4. If `count >= maxRequests`, check if a block record exists (`waf:block:<ip>`). If not, create one with TTL = `blockDurationMs`. Return 429.
5. Otherwise, increment `count` and update the store.

The window is not reset on each request — it starts at the first request and expires `windowMs` milliseconds later. This is a true sliding window (per first-request start), not a fixed-interval bucket.

The in-memory store uses a `Map` with a periodic cleanup interval to avoid unbounded memory growth.

---

## How IP filtering works

`utils/ipUtils.js` provides `ipMatchesCidr(ip, cidr)` using pure arithmetic — no external dependencies.

**IPv4 CIDR matching:**
1. Split CIDR into address and prefix length.
2. Convert both the test IP and the CIDR base address to 32-bit integers.
3. Apply the subnet mask and compare.

**IPv6 CIDR matching:**
1. Normalize IPv6 addresses to full 128-bit representation (expand `::`, handle IPv4-mapped `::ffff:a.b.c.d`).
2. Split into two 64-bit halves (JavaScript's `Number` cannot hold 128-bit integers without loss).
3. Apply prefix mask to each half and compare.

Both IPv4 and IPv6 addresses are supported in `whitelist`, `blacklist`, and `trustedProxies`.

---

## Node.js vs PHP — architectural differences

| Aspect | Node.js | PHP |
|--------|---------|-----|
| Entry point | `createWAF()` returns middleware array | `waf.php` auto-prepend executes on every request |
| Request lifecycle | Express middleware chain | Sequential PHP function calls in `WAF.php` |
| Pattern matching | `patternMatcher.js` — `deepDecode()` + `scanSources()` | `Request.php` — same logic in PHP |
| Rate limit store | Pluggable: in-memory Map or custom (Redis) | APCu shared memory or file-based fallback |
| Concurrent writes | Node.js event loop (single thread, no locking needed) | `flock()` exclusive lock per log write |
| Configuration | `waf.config.js` (JS object) + `createWAF(options)` overrides | `waf.config.php` (PHP array, no runtime override) |
| Debug headers | Added by `debug.js` middleware | Added by `WAF.php` before response exits |
| Bot list | `config/bad-bots.json` | `config/bad-bots.php` |
| Pipeline stages | 23 (includes debug stage 0) | 22 |
| TypeScript | `index.d.ts` bundled | Not applicable |
