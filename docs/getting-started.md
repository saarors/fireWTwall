# Getting Started

## Prerequisites

**Node.js:** Node >= 16, Express (any version supported by Node 16+).

**PHP:** PHP >= 8.0. The APCu extension is optional but recommended for production rate limiting.

---

## Node.js — 5-line setup

```bash
npm install firewtwall
```

```js
const express = require('express');
const { createWAF } = require('firewtwall');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(...createWAF());
app.listen(3000);
```

Body parsers **must** come before `createWAF()` so the WAF can inspect parsed request bodies. See [nodejs/installation.md](nodejs/installation.md) for the full explanation.

---

## PHP — minimal setup

**Option A (recommended): Composer**

```bash
composer require saarors/firewtwall-php
```

Then in your entry point (`index.php` or equivalent):

```php
<?php
require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/vendor/saarors/firewtwall-php/php/waf.php';
```

**Option B: php.ini global auto-prepend (no Composer)**

```ini
auto_prepend_file = /absolute/path/to/fireWTwall/php/waf.php
```

This fires the WAF before every PHP script on the server without changing any application code. See [php/installation.md](php/installation.md) for all four install options including `.htaccess` and manual `require`.

---

## Verify it works

Start your server, then run:

```bash
# Clean request — should return 200
curl -i http://localhost:3000/

# SQL injection — should return 403
curl -i "http://localhost:3000/?q=1+UNION+SELECT+*+FROM+users"

# XSS — should return 403
curl -i "http://localhost:3000/?q=<script>alert(1)</script>"
```

The blocked requests are logged to `./logs/waf.log` in NDJSON format. View them with:

```bash
npx waf-log --blocked
```

---

## Next steps

- [nodejs/configuration.md](nodejs/configuration.md) — tune mode, rate limits, whitelists, and more
- [nodejs/debug-mode.md](nodejs/debug-mode.md) — enable full request tracing for development
- [log-format.md](log-format.md) — understand every field in the log
- [false-positives.md](false-positives.md) — what to do if a legitimate request is blocked
