# ASP.NET Debug Mode

## Enable debug mode

```csharp
// Global.asax.cs
protected void Application_Start(object sender, EventArgs e)
{
    WafConfig.Current.Debug = true;
}
```

> ⚠️ **Never enable in production.** Debug mode adds `X-WAF-Rule` headers that expose your internal rule names to any client — including attackers who can use them to craft bypass attempts.

---

## What changes in debug mode

| What | Normal mode | Debug mode |
|------|-------------|------------|
| Passing requests | Not logged | Logged with `durationMs` and `requestId` |
| Blocked requests | Logged | Logged (same as normal) |
| `X-WAF-RequestId` response header | Not sent | Always sent |
| `X-WAF-Result` response header | Not sent | `"passed"` or `"blocked"` |
| `X-WAF-Rule` response header | Not sent | Rule name on blocked requests |
| `X-WAF-Time` response header | Not sent | Processing time in ms |

---

## Response headers in debug mode

```
X-WAF-RequestId: a1b2c3d4e5f6a7b8
X-WAF-Result: blocked
X-WAF-Rule: sql-union-select
X-WAF-Time: 0.83ms
```

---

## Log entries in debug mode

**Passing request:**

```json
{
  "timestamp": "2026-04-01T10:00:00Z",
  "requestId": "f47ac10b58cc1122",
  "result": "passed",
  "ip": "127.0.0.1",
  "method": "GET",
  "path": "/products",
  "userAgent": "Mozilla/5.0 ...",
  "durationMs": 0.42
}
```

**Blocked request:**

```json
{
  "timestamp": "2026-04-01T10:00:01Z",
  "requestId": "a1b2c3d4e5f6a7b8",
  "result": "blocked",
  "ip": "203.0.113.42",
  "method": "GET",
  "path": "/search",
  "rule": "sql-union-select",
  "matched": "UNION SELECT",
  "source": "query",
  "severity": "critical",
  "userAgent": "sqlmap/1.7",
  "durationMs": 0.83
}
```

---

## View logs during development

The WAF writes NDJSON to `App_Data/waf.log` (default path). You can tail it in PowerShell:

```powershell
Get-Content .\App_Data\waf.log -Wait | ForEach-Object { $_ | ConvertFrom-Json }
```

Or filter for blocked requests only:

```powershell
Get-Content .\App_Data\waf.log |
    ConvertFrom-Json |
    Where-Object { $_.result -eq "blocked" } |
    Format-Table timestamp, ip, rule, severity, matched -AutoSize
```

Or use `jq` if you have it installed:

```bash
tail -f App_Data/waf.log | jq 'select(.result == "blocked")'
```

---

## Useful debug workflow

1. Enable debug mode in `Application_Start`.
2. Send a request you suspect may be blocked:
   ```bash
   curl -v "http://localhost/?q=hello"
   ```
3. Check the `X-WAF-*` response headers to see the rule and processing time.
4. Check `App_Data/waf.log` for the full log entry.
5. If it's a false positive, see [false-positives.md](../false-positives.md).
6. Disable `Debug = true` before deploying.
