# PHP Rate Limiter

## Backends

The PHP WAF supports two rate-limiting backends. The active backend is selected automatically at runtime.

| Backend | When used | Characteristics |
|---------|-----------|-----------------|
| **APCu** | `ext-apcu` is loaded and `apc.enabled=1` | Fast, atomic shared memory across all PHP-FPM workers |
| **File-based** | APCu not available (fallback) | Uses `sys_get_temp_dir()` — safe on shared hosting, not atomic |

---

## How APCu works

APCu stores rate-limit counters in shared memory. Because all PHP-FPM worker processes share the same APCu memory pool, counters are accurate across concurrent requests.

The rate limiter uses a sliding-window algorithm:

1. On each request, fetch the counter for the client IP.
2. If no counter exists or the window has expired, create a new one with `count = 1`.
3. If the counter exists and is within the window, increment it.
4. If `count > max_requests`, block the IP and set a block entry with TTL = `block_duration_sec`.
5. Blocked IPs are checked first — a blocked IP is rejected immediately without incrementing the counter.

APCu key format: `waf_rl_{ip}` for rate counters, `waf_block_{ip}` for active blocks.

---

## How the file-based fallback works

When APCu is not available, counters are stored as JSON files in `sys_get_temp_dir()` (typically `/tmp`):

- File name: `waf_rl_{ip_hash}.json` (IP is hashed to avoid filesystem special characters)
- File locking: `flock()` with exclusive lock for writes, shared lock for reads
- Stale files (older than window + block_duration) are cleaned up on read

The file-based backend is safe but not atomic. Under very high concurrent load a small number of requests may slip through above the limit due to race conditions between processes reading and writing the same counter file.

---

## How to enable APCu

1. Install the extension:

```bash
# Debian / Ubuntu
apt install php8.2-apcu

# RHEL / CentOS
yum install php-pecl-apcu

# macOS (Homebrew)
pecl install apcu
```

2. Add to `php.ini`:

```ini
extension=apcu
apc.enabled=1
apc.shm_size=64M     ; adjust to match your expected traffic
apc.ttl=3600
```

3. For PHP-FPM, ensure APCu is also enabled in CLI if you run scripts that interact with the rate limiter:

```ini
; In php.ini or /etc/php/8.2/cli/conf.d/20-apcu.ini
apc.enable_cli=1
```

4. Restart PHP-FPM:

```bash
systemctl restart php8.2-fpm
```

---

## Shared hosting considerations

Most shared hosting environments do not provide APCu. The file-based fallback is designed to work in this scenario:

- No system dependencies — only PHP's built-in `flock()` and `file_put_contents()`
- Works correctly on single-server deployments
- Not suitable for multi-server deployments (each server has its own `/tmp`)

For multi-server shared hosting, consider placing a reverse proxy (nginx, Cloudflare) in front and enforcing rate limits at the proxy level.

---

## How to check which backend is active

Add a temporary diagnostic script (remove after checking):

```php
<?php
if (function_exists('apcu_fetch') && ini_get('apc.enabled')) {
    echo "Rate limiter: APCu (shared memory)\n";
} else {
    echo "Rate limiter: file-based (fallback)\n";
    echo "Temp dir: " . sys_get_temp_dir() . "\n";
}
```

Or check the WAF source — `php/src/RateLimiter.php` contains a constructor that selects the backend and logs which one is active when `debug` is enabled.

---

## Rate limit configuration

```php
'rate_limit' => [
    'window_sec'         => 60,   // 60-second sliding window
    'max_requests'       => 100,  // 100 requests per window per IP
    'block_duration_sec' => 600,  // 10-minute block after violation
],
```

When the limit is exceeded, the WAF returns:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 600
```
