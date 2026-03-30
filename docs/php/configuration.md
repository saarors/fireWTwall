# PHP Configuration Reference

Edit `php/config/waf.config.php` to customize the WAF. The file returns a plain PHP array.

```php
<?php
return [
    'allowed_methods'   => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
    'max_body_size'     => 10 * 1024 * 1024,
    'rate_limit'        => [
        'window_sec'         => 60,
        'max_requests'       => 100,
        'block_duration_sec' => 600,
    ],
    'whitelist'         => [],
    'blacklist'         => [],
    'bypass_paths'      => ['/health', '/ping'],
    'trusted_proxies'   => [],
    'mode'              => 'reject',
    'log_path'          => __DIR__ . '/../logs/waf.log',
    'response_type'     => 'json',
    'debug'             => false,
];
```

---

## All options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `allowed_methods` | `string[]` | `['GET','POST','PUT','PATCH','DELETE','OPTIONS','HEAD']` | HTTP verbs that are permitted. Any other verb returns 405. |
| `max_body_size` | `int` | `10485760` | Maximum request body size in bytes (10 MB). Requests exceeding this return 413. |
| `rate_limit.window_sec` | `int` | `60` | Sliding window duration in seconds. |
| `rate_limit.max_requests` | `int` | `100` | Maximum requests allowed per IP per window. |
| `rate_limit.block_duration_sec` | `int` | `600` | How long (seconds) an IP stays blocked after exceeding the limit. |
| `whitelist` | `string[]` | `[]` | IPs or CIDR ranges that bypass all WAF checks (rate limiting included). |
| `blacklist` | `string[]` | `[]` | IPs or CIDR ranges that are always blocked with 403. |
| `bypass_paths` | `string[]` | `['/health', '/ping']` | URL paths that skip all WAF checks. Prefix match on `$_SERVER['REQUEST_URI']`. |
| `trusted_proxies` | `string[]` | `[]` | IPs of trusted reverse proxies. When set, client IP is read from `HTTP_X_FORWARDED_FOR`. |
| `mode` | `string` | `'reject'` | `'reject'` blocks and exits. `'log-only'` logs but lets requests through. |
| `log_path` | `string` | `__DIR__ . '/../logs/waf.log'` | Absolute path for the NDJSON log file. Must be writable and not web-accessible. |
| `response_type` | `string` | `'json'` | Block response format: `'json'` or `'html'`. |
| `debug` | `bool` | `false` | Log every request and add `X-WAF-*` response headers. Never use in production. |

---

## mode: log-only

Start in audit mode to find false positives before enforcing:

```php
'mode' => 'log-only',
```

Review `logs/waf.log`, confirm no legitimate traffic is flagged, then switch to `'reject'`.

---

## trusted_proxies

If your application sits behind nginx or a load balancer, set the proxy's IP so the real client IP is used for rate limiting and IP filtering:

```php
'trusted_proxies' => ['10.0.0.1', '10.0.0.0/8'],
```

Only set this to IPs you control. An attacker who can forge `X-Forwarded-For` headers could otherwise spoof their IP.

---

## whitelist and blacklist

Both accept individual IPs and CIDR notation. IPv4 and IPv6 are supported:

```php
'whitelist' => [
    '127.0.0.1',
    '::1',
    '10.0.0.0/8',
    '192.168.1.0/24',
],
'blacklist' => [
    '203.0.113.0/24',
    '198.51.100.42',
],
```

Whitelist takes priority: an IP that matches both lists is allowed.

---

## APCu setup

APCu enables fast, atomic rate limiting shared across all PHP-FPM workers. Without it, the WAF falls back to file-based rate limiting (safe, but not atomic under heavy concurrent load).

Enable in `php.ini`:

```ini
extension=apcu
apc.enabled=1
apc.shm_size=64M
```

Restart PHP-FPM after changing `php.ini`:

```bash
systemctl restart php8.2-fpm
```

Verify APCu is active:

```php
<?php var_dump(function_exists('apcu_fetch')); // bool(true)
```

See [rate-limiter.md](rate-limiter.md) for the full comparison.

---

## debug flag

```php
'debug' => true,
```

Adds `X-WAF-RequestId`, `X-WAF-Result`, `X-WAF-Rule` (blocked only), and `X-WAF-Time` headers to every response. Logs both passed and blocked requests.

Never enable in production. See [debug-mode.md](debug-mode.md).

---

## Custom log path

```php
'log_path' => '/var/log/myapp/waf.log',
```

Ensure the directory exists and is writable before deploying:

```bash
mkdir -p /var/log/myapp
chown www-data:www-data /var/log/myapp
chmod 750 /var/log/myapp
```
