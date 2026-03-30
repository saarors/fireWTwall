# Debug Mode (Node.js)

## How to enable

```js
app.use(...createWAF({ debug: true }));
```

Debug mode is per-`createWAF()` call. It has no effect on other middleware.

---

## What changes in debug mode

| Behavior | Normal mode | Debug mode |
|----------|------------|------------|
| Blocked requests logged | Yes | Yes |
| Passed requests logged | No | Yes |
| `X-WAF-*` response headers | No | Yes |
| Processing time in log | No | Yes |
| `checksRun` field in log | No | Yes |
| Matched value in log | Yes (blocked only) | Yes |

---

## X-WAF-* response headers

These four headers are added to every response when `debug: true`:

| Header | Example value | Present when |
|--------|--------------|--------------|
| `X-WAF-RequestId` | `f47ac10b58cc1122` | Always |
| `X-WAF-Result` | `passed` or `blocked` | Always |
| `X-WAF-Rule` | `sql-union-select` | Blocked requests only |
| `X-WAF-Time` | `0.83ms` | Always |

Use these headers from your HTTP client or browser devtools to confirm which rule fired on a particular request.

```bash
# See all X-WAF-* headers for a blocked request
curl -si "http://localhost:3000/?q=UNION+SELECT+*+FROM+users" | grep X-WAF
# X-WAF-RequestId: f47ac10b58cc1122
# X-WAF-Result: blocked
# X-WAF-Rule: sql-union-select
# X-WAF-Time: 0.83ms
```

```bash
# See headers for a clean request
curl -si http://localhost:3000/ | grep X-WAF
# X-WAF-RequestId: a8b4c2d1e9f03847
# X-WAF-Result: passed
# X-WAF-Time: 0.21ms
```

---

## Sample log entries

**Passed request (debug mode only):**
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

**Blocked request:**
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

---

## waf-log CLI in debug mode

When `debug: true` is set, the log contains both `passed` and `blocked` entries. Use the CLI flags to filter:

```bash
# Show only blocked requests
npx waf-log --blocked

# Show only passed requests
npx waf-log --passed

# Show everything from the last hour
npx waf-log --since 2026-03-30T09:00:00Z

# Filter blocked requests by a specific IP
npx waf-log --blocked --ip 203.0.113.42

# Raw NDJSON — pipe to jq for custom queries
npx waf-log --json | jq 'select(.result == "blocked" and .severity == "critical")'
```

For the full CLI reference see [cli.md](cli.md).

---

## Catching bots and scanners in development

```bash
# Simulate an nmap probe at your dev server
nmap -sV localhost -p 3000

# Then check the log
npx waf-log --blocked --rule bot

# Or watch in real time
watch -n 2 'npx waf-log --tail 10 --blocked'
```

---

## Production warning

Never use `debug: true` in production. It has two concrete risks:

1. **Information leakage** — `X-WAF-Rule` tells an attacker exactly which rule name matched and which variant of their payload was detected, helping them craft obfuscated bypasses.
2. **Log volume** — Every request — including high-frequency health checks and asset requests — produces a log entry, which can fill disk quickly on busy servers.
