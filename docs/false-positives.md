# Handling False Positives

A false positive is a legitimate request that the WAF incorrectly blocks. This guide explains how to identify, diagnose, and resolve them.

---

## Step 1 — Start in log-only mode

Before enforcing blocks in production, run in audit mode:

**Node.js:**
```js
app.use(...createWAF({ mode: 'log-only' }));
```

**PHP (`waf.config.php`):**
```php
'mode' => 'log-only',
```

In `log-only` mode, every potentially malicious request is logged but not blocked. This lets you audit traffic and find false positives without affecting users.

---

## Step 2 — Read the logs to find which rule fired

```bash
# Show recent blocked-candidate entries
npx waf-log --tail 50

# Filter by a specific rule
npx waf-log --rule sql

# Find all rules that have fired, sorted by frequency
npx waf-log --json | jq -r '.rule // empty' | sort | uniq -c | sort -rn
```

Each log entry tells you:
- `rule` — which rule matched
- `source` — where in the request (query, body, cookie, header)
- `matched` — the exact substring that triggered the rule

**Example log entry for a false positive:**
```json
{
  "rule": "sql-comment",
  "matched": "--",
  "source": "query",
  "severity": "high",
  "path": "/api/search",
  "ip": "10.0.1.5"
}
```

The `sql-comment` rule matched `--` in the search query — a user typed a double-dash in a search field.

---

## Step 3 — Choose the right resolution

### Option A — Use log-only mode longer

If the false positive rate is low and you are still learning your traffic patterns, remain in `log-only` mode and continue monitoring before enforcing.

### Option B — Bypass paths for specific routes

If a specific route legitimately receives data that triggers rules (e.g., a code editor, a search endpoint for SQL documentation), bypass the WAF for that route:

**Node.js:**
```js
app.use(...createWAF({
  bypassPaths: ['/health', '/api/code-editor', '/docs/sql'],
}));
```

**PHP:**
```php
'bypass_paths' => ['/health', '/api/code-editor', '/docs/sql'],
```

`bypassPaths` is an exact match on the URL path. The WAF does not evaluate any rules for these paths — no rate limiting, no logging, no rule checks.

### Option C — Whitelist trusted IPs

If the false positive comes from a trusted internal service, CI/CD agent, or known IP:

**Node.js:**
```js
app.use(...createWAF({
  whitelist: ['10.0.0.0/8', '172.16.0.0/12'],
}));
```

**PHP:**
```php
'whitelist' => ['10.0.0.0/8', '172.16.0.0/12'],
```

Whitelisted IPs bypass all WAF checks.

---

## Common legitimate patterns that may trigger rules

### Double-dash in user content (`sql-comment`)

A user comment or text field containing `--` (Markdown horizontal rule, code comments, abbreviations like `--flag`) matches the SQL comment rule.

**Resolution:** If the endpoint receives user-authored content, consider `bypassPaths` or moving the endpoint to a path that is excluded.

### Base64 in query parameters (`sql-hex-values`, `deser-java-b64`)

A parameter that carries base64-encoded data may accidentally match rules looking for hex strings or Java serialization headers (`rO0AB`).

**Resolution:** If your application passes base64 data via URL parameters, consider:
- Moving it to a POST body
- Using a different encoding (URL-safe base64 without `+` or `=`)
- Using `bypassPaths` for the specific endpoint

### Double-encoded URLs in proxy scenarios (`path-traversal-encoded`)

Reverse proxies sometimes double-encode URL components. A URL like `/files/%252F../` becomes `%2F../` after one decode, which matches path traversal.

**Resolution:** Configure your proxy to not double-encode paths, or add `trustedProxies` so the WAF sees the original decoded URL.

### Template syntax in search queries (`ssti-angularjs-bind`, `xss-template-literal`)

Search queries containing `{{` or `${` (e.g., searching for code examples) may trigger SSTI or XSS template rules.

**Resolution:** Use `bypassPaths` for search endpoints that accept code snippets, or implement application-level input validation and context-aware encoding.

### SQL keywords in legitimate content (`sql-comment`, `sql-boolean-true`)

Content like database documentation, a SQL tutorial endpoint, or a blog post about SQL might contain `SELECT`, `--`, `OR 1=1`, etc.

**Resolution:** Use `bypassPaths` for the content management endpoints.

---

## How to report a false positive

If you believe a rule produces excessive false positives for common legitimate inputs (not application-specific data), open an issue at:

https://github.com/saarors/fireWTwall/issues

Include:
- The rule ID (`rule` field in the log)
- The matched value (redact sensitive data)
- The source (query, body, header, etc.)
- A description of the legitimate use case that triggers it
