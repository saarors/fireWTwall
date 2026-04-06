# ASP.NET Configuration

## Overview

All settings live in the `WafConfig.Current` singleton. Override defaults in `Application_Start` inside `Global.asax.cs` — before the first request arrives.

```csharp
// Global.asax.cs
protected void Application_Start(object sender, EventArgs e)
{
    WafConfig.Current.Mode              = "reject";   // or "log-only"
    WafConfig.Current.Debug             = false;
    WafConfig.Current.ResponseType      = "json";     // or "html"

    WafConfig.Current.RateLimit.MaxRequests       = 100;
    WafConfig.Current.RateLimit.WindowSec         = 60;
    WafConfig.Current.RateLimit.BlockDurationSec  = 600;

    WafConfig.Current.MaxBodySize       = 10 * 1024 * 1024;  // 10 MB

    WafConfig.Current.Whitelist         = new[] { "127.0.0.1", "10.0.0.0/8" };
    WafConfig.Current.Blacklist         = new[] { "203.0.113.42" };
    WafConfig.Current.BypassPaths       = new[] { "/health", "/ping" };
    WafConfig.Current.TrustedProxies    = new[] { "172.16.0.1" };

    WafConfig.Current.AllowedMethods    = new[]
        { "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD" };

    // Custom log path (must be writable by IIS app pool, not web-accessible)
    WafConfig.Current.LogPath           = @"C:\Logs\myapp\waf.log";

    // Customise bot detection
    WafBotConfigProvider.Config.BlockEmptyUserAgent = true;
}
```

---

## Configuration reference

### Top-level settings

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Mode` | `string` | `"reject"` | `"reject"` blocks and returns 4xx · `"log-only"` logs but lets requests through |
| `MaxBodySize` | `int` | `10485760` | Maximum `Content-Length` in bytes (10 MB) |
| `AllowedMethods` | `string[]` | `GET POST PUT PATCH DELETE OPTIONS HEAD` | HTTP verbs that are allowed — everything else returns 405 |
| `Whitelist` | `string[]` | `[]` | IPs or CIDR ranges that bypass all WAF checks |
| `Blacklist` | `string[]` | `[]` | IPs or CIDR ranges that are always blocked |
| `BypassPaths` | `string[]` | `["/health", "/ping"]` | URL path prefixes that skip all WAF checks |
| `TrustedProxies` | `string[]` | `[]` | IPs of trusted reverse proxies — enables `X-Forwarded-For` parsing |
| `LogPath` | `string` | `App_Data/waf.log` | Absolute or relative path to the NDJSON log file |
| `ResponseType` | `string` | `"json"` | Block response format: `"json"` or `"html"` |
| `Debug` | `bool` | `false` | Enables full request tracing and `X-WAF-*` response headers (see [debug-mode.md](debug-mode.md)) |

---

### Rate limit (`WafConfig.Current.RateLimit`)

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `WindowSec` | `int` | `60` | Sliding window size in seconds |
| `MaxRequests` | `int` | `100` | Maximum requests allowed per IP per window |
| `BlockDurationSec` | `int` | `600` | How long to block an IP after it exceeds the rate limit (10 min) |

Rate limiting uses `System.Runtime.Caching.MemoryCache` — shared across all IIS threads in the AppDomain. For multi-server deployments, the limit is per-server (each instance maintains its own counters).

---

### DDoS protection (`WafConfig.Current.Ddos`)

| Property | Default | Description |
|----------|---------|-------------|
| `MaxUrlLength` | `2048` | Maximum URL length in bytes — returns 414 if exceeded |
| `MaxHeaderCount` | `100` | Maximum number of HTTP headers — returns 431 if exceeded |
| `MaxHeaderSize` | `8192` | Maximum length of any single header value — returns 431 if exceeded |
| `Burst.WindowSec` | `1` | Burst window in seconds |
| `Burst.MaxRequests` | `20` | Maximum requests per IP in the burst window |
| `Burst.BlockDurationSec` | `60` | How long to block after a burst violation |
| `Global.WindowSec` | `1` | Global counter window in seconds |
| `Global.MaxRequests` | `500` | Maximum total requests across all IPs in the window — returns 503 |
| `Fingerprint.WindowSec` | `10` | Fingerprint flood window (IP + UA + path) |
| `Fingerprint.MaxRequests` | `50` | Maximum identical fingerprint requests in window |
| `Fingerprint.BlockDurationSec` | `60` | Block duration after fingerprint flood |
| `PathFlood.WindowSec` | `5` | Path flood window (cross-IP, same endpoint) |
| `PathFlood.MaxRequests` | `200` | Maximum requests to the same path in the window |
| `Tarpit.Enabled` | `false` | Delay repeat burst offenders instead of immediately blocking |
| `Tarpit.DelayMs` | `2000` | Milliseconds to sleep before responding to tarpitted IPs |

---

### Bot detection (`WafBotConfigProvider.Config`)

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `BlockEmptyUserAgent` | `bool` | `true` | Block requests that send no `User-Agent` header |
| `Blocked` | `string[]` | 70+ signatures | Substrings matched case-insensitively against the `User-Agent` header |
| `Allowed` | `string[]` | Major search engines | User-Agent substrings that are always allowed (checked before `Blocked`) |

To add or remove bot signatures at startup:

```csharp
// Add a custom blocked tool
var cfg = WafBotConfigProvider.Config;
var blocked = new System.Collections.Generic.List<string>(cfg.Blocked);
blocked.Add("my-internal-scanner");
cfg.Blocked = blocked.ToArray();
WafBotConfigProvider.Config = cfg;
```

---

## CIDR notation

Both `Whitelist`, `Blacklist`, and `TrustedProxies` accept individual IPs or CIDR ranges:

```csharp
WafConfig.Current.Whitelist = new[]
{
    "127.0.0.1",           // single IPv4
    "::1",                 // single IPv6 (loopback)
    "10.0.0.0/8",          // IPv4 CIDR
    "192.168.1.0/24",      // IPv4 subnet
    "2001:db8::/32",       // IPv6 CIDR
};
```

---

## Mode recommendation

| Deployment stage | Recommended mode |
|-----------------|-----------------|
| First deploy / audit | `"log-only"` — observe without impacting users |
| After reviewing logs | `"reject"` — actively block threats |

Always start with `log-only`. Review `App_Data/waf.log` for false positives before switching to `reject`. See [false-positives.md](../false-positives.md) for guidance.
