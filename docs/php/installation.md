# PHP Installation

## Requirements

- PHP >= 8.0
- APCu extension — optional but recommended for production rate limiting (see [rate-limiter.md](rate-limiter.md))
- `ext-intl` — optional, enables Unicode NFKC normalization for advanced evasion detection

---

## Option A — Composer (recommended)

```bash
composer require saarors/firewtwall-php
```

Then load the WAF at the top of your entry point:

```php
<?php
require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/vendor/saarors/firewtwall-php/php/waf.php';
// Your application code follows
```

The WAF runs synchronously — it either exits with a 403 response or returns control to your application.

**With `php.ini` after Composer install** (runs before every script automatically):

```ini
auto_prepend_file = /path/to/vendor/saarors/firewtwall-php/php/waf.php
```

---

## Option B — php.ini auto_prepend_file (server-wide, no Composer)

1. Clone or copy the `php/` directory to a permanent location:

```bash
git clone https://github.com/saarors/fireWTwall.git /opt/firewtwall
```

2. Edit `php.ini`:

```ini
auto_prepend_file = /opt/firewtwall/php/waf.php
```

3. Reload PHP-FPM or restart Apache:

```bash
systemctl reload php8.2-fpm
# or
systemctl restart apache2
```

This applies the WAF to every PHP script on the server. Configuration is read from `php/config/waf.config.php`.

---

## Option C — .htaccess (per-directory, Apache)

To protect a specific directory without editing `php.ini`:

```apache
php_value auto_prepend_file "/opt/firewtwall/php/waf.php"
```

Place this in the `.htaccess` file of the directory you want to protect. Requires `AllowOverride Options` or `AllowOverride All` in the Apache virtual host configuration.

---

## Option D — Manual require (any framework)

```php
<?php
require_once '/opt/firewtwall/php/waf.php';
// Application bootstraps here
```

Place this at the very top of your front controller (e.g. `public/index.php`) before any framework bootstrapping.

---

## Configuration

Edit `php/config/waf.config.php` to customize mode, rate limits, whitelists, and more. See [configuration.md](configuration.md) for every option.

---

## Protecting the logs/ directory

The WAF writes NDJSON logs to `php/logs/waf.log` by default. This directory must be:

1. **Writable** by the web server user (`www-data`, `apache`, etc.)
2. **Not web-accessible** — log files contain full request details including IPs and matched payloads

The included `php/logs/.htaccess` handles this automatically for Apache:

```apache
Deny from all
```

For nginx, add a location block to your server configuration:

```nginx
location ~ /firewtwall/php/logs/ {
    deny all;
}
```

To make the logs directory writable:

```bash
chown www-data:www-data /opt/firewtwall/php/logs
chmod 750 /opt/firewtwall/php/logs
```

---

## Verifying the install

After installation, test with a known attack:

```bash
# SQL injection — should return 403
curl -i "https://your-site.com/?q=1+UNION+SELECT+*+FROM+users"

# Clean request — should return 200
curl -i "https://your-site.com/"
```

Check the log:

```bash
tail -f /opt/firewtwall/php/logs/waf.log | python3 -m json.tool
```
