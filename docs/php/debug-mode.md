# Debug Mode (PHP)

## How to enable

In `php/config/waf.config.php`:

```php
'debug' => true,
```

Restart PHP-FPM if you use OPcache (config file may be cached):

```bash
systemctl reload php8.2-fpm
```

---

## X-WAF-* response headers

When debug is enabled, four headers are added to every response:

| Header | Example value | Present when |
|--------|--------------|--------------|
| `X-WAF-RequestId` | `f47ac10b58cc1122` | Always |
| `X-WAF-Result` | `passed` or `blocked` | Always |
| `X-WAF-Rule` | `sql-union-select` | Blocked requests only |
| `X-WAF-Time` | `0.83ms` | Always |

Verify with curl:

```bash
# Clean request
curl -si https://your-site.com/ | grep X-WAF
# X-WAF-RequestId: a8b4c2d1e9f03847
# X-WAF-Result: passed
# X-WAF-Time: 0.31ms

# Attack request
curl -si "https://your-site.com/?q=1+UNION+SELECT+*+FROM+users" | grep X-WAF
# X-WAF-RequestId: f47ac10b58cc1122
# X-WAF-Result: blocked
# X-WAF-Rule: sql-union-select
# X-WAF-Time: 0.91ms
```

---

## Log verbosity

In normal mode only blocked requests are logged. In debug mode every request produces a log entry.

**Passed request log entry (debug mode only):**
```json
{
  "timestamp": "2026-03-30T10:00:00Z",
  "requestId": "f47ac10b58cc1122",
  "ip": "127.0.0.1",
  "method": "GET",
  "path": "/",
  "result": "passed",
  "processingTimeMs": 0.31
}
```

**Blocked request log entry:**
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
  "source": "query",
  "severity": "critical",
  "processingTimeMs": 0.91,
  "userAgent": "sqlmap/1.7"
}
```

---

## Reading debug logs

The PHP WAF writes the same NDJSON format as the Node.js version. Use `jq` or the `waf-log` CLI (if the Node.js package is also installed) to query them:

```bash
# All entries
cat logs/waf.log | python3 -m json.tool

# Only blocked (jq)
cat logs/waf.log | jq 'select(.result == "blocked")'

# All critical severity events
cat logs/waf.log | jq 'select(.severity == "critical")'

# Top rules
cat logs/waf.log | jq -r '.rule // empty' | sort | uniq -c | sort -rn
```

See [log-format.md](../log-format.md) for every field definition.

---

## Production warning

Never use `debug: true` in production:

1. **`X-WAF-Rule` leaks rule names** — an attacker who sees exactly which rule name matched can craft obfuscated payloads to evade that specific check.
2. **Log volume** — Every request produces a log entry. On a busy server this can fill disk within hours.
3. **Processing overhead** — Generating request IDs and computing timestamps for every request adds measurable latency under high concurrency.
