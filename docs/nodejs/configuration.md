# Node.js Configuration Reference

Pass an options object to `createWAF()`. All keys are optional — defaults shown below.

```js
const { createWAF, setStore } = require('firewtwall');

app.use(...createWAF({
  mode: 'reject',
  rateLimit: {
    windowMs:        60_000,
    maxRequests:     100,
    blockDurationMs: 600_000,
  },
  whitelist:      ['127.0.0.1', '10.0.0.0/8'],
  blacklist:      ['203.0.113.0/24'],
  bypassPaths:    ['/health', '/metrics'],
  trustedProxies: ['172.16.0.1'],
  logPath:        './logs/waf.log',
  responseType:   'json',
  debug:          false,
}));
```

---

## All options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | `string` | `'reject'` | `'reject'` blocks and returns 403. `'log-only'` logs but lets requests through. |
| `allowedMethods` | `string[]` | `['GET','POST','PUT','PATCH','DELETE','OPTIONS','HEAD']` | HTTP verbs that are permitted. Any other verb returns 405. |
| `maxBodySize` | `number` | `10485760` | Maximum `Content-Length` in bytes (10 MB). Requests with a larger declared body return 413. |
| `rateLimit` | `object` | See below | Rate limiting configuration. |
| `rateLimit.windowMs` | `number` | `60000` | Sliding window duration in milliseconds. |
| `rateLimit.maxRequests` | `number` | `100` | Maximum requests allowed per IP per window. |
| `rateLimit.blockDurationMs` | `number` | `600000` | How long (ms) an IP stays blocked after exceeding the limit. Returns 429 with `Retry-After`. |
| `whitelist` | `string[]` | `[]` | IPs or CIDR ranges that bypass all WAF checks entirely (rate limiting included). |
| `blacklist` | `string[]` | `[]` | IPs or CIDR ranges that are always blocked with 403, regardless of content. |
| `bypassPaths` | `string[]` | `['/health', '/ping']` | Exact path matches that skip all WAF checks. Useful for health-check and metrics endpoints. |
| `trustedProxies` | `string[]` | `[]` | IPs of trusted reverse proxies. When set, the client IP is read from `X-Forwarded-For` instead of the socket. |
| `logPath` | `string` | `'./logs/waf.log'` | Absolute or relative path for the NDJSON log file. The directory must exist and be writable. |
| `responseType` | `string` | `'json'` | Format of block responses: `'json'` returns `{"blocked":true,"rule":"...","message":"..."}`. `'html'` returns a minimal HTML error page. |
| `debug` | `boolean` | `false` | Enables full request tracing and `X-WAF-*` response headers. Never use in production. See [debug-mode.md](debug-mode.md). |

---

## rateLimit in depth

The rate limiter uses a sliding window algorithm per IP. The window resets `windowMs` milliseconds after the **first** request in a window, not after a fixed clock interval.

```js
rateLimit: {
  windowMs:        60_000,   // 60-second window
  maxRequests:     100,      // 100 requests allowed per window per IP
  blockDurationMs: 600_000,  // IP blocked for 10 minutes after violation
}
```

When an IP is blocked the response includes:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 600
```

By default the rate limiter uses an in-memory store, which is **per-process**. In multi-process deployments (PM2 cluster, multiple Node instances) each process has its own counter. Use Redis for shared state: see [redis.md](redis.md).

---

## trustedProxies

When your app sits behind a reverse proxy (nginx, Cloudflare, AWS ALB), the socket `remoteAddress` will be the proxy's IP, not the client's. Set `trustedProxies` to the proxy's IP so that `X-Forwarded-For` is used for rate limiting and IP filtering:

```js
trustedProxies: ['10.0.0.1', '10.0.0.0/8']
```

Only list IPs you control. An attacker who can set `X-Forwarded-For` arbitrarily could spoof their IP to bypass the blacklist or exhaust rate-limit slots for legitimate IPs.

---

## bypassPaths

Paths listed here skip all WAF middleware entirely — no rule evaluation, no rate limiting, no logging. Use for:

- Health-check endpoints polled by load balancers
- Prometheus/metrics scrape endpoints
- Internal callback endpoints where you control the payload

```js
bypassPaths: ['/health', '/ping', '/metrics', '/_internal/status']
```

Matching is an **exact** match on `req.path`. Query strings and trailing slashes are not stripped. `/health?foo=bar` does **not** match `/health`.

---

## whitelist vs bypassPaths

| | `whitelist` | `bypassPaths` |
|---|---|---|
| Matches on | IP address | URL path |
| Still rate-limited | No | No |
| Still logged (debug mode) | Yes | No |
| Use case | Your own servers, CI/CD agents | Health checks, internal routes |

---

## mode: log-only

Start new deployments in `log-only` mode to audit traffic without blocking. Review `waf.log` for false positives, then switch to `reject`:

```js
// Phase 1 — audit
app.use(...createWAF({ mode: 'log-only' }));

// Phase 2 — enforce
app.use(...createWAF({ mode: 'reject' }));
```

See [false-positives.md](../false-positives.md) for how to read the logs.
