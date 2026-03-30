# Node.js Installation

## Requirements

- Node.js >= 16
- Express (any version — firewtwall has zero runtime dependencies)

---

## Install

```bash
npm install firewtwall
```

---

## Minimal setup

```js
const express = require('express');
const { createWAF } = require('firewtwall');

const app = express();

// Body parsers MUST come before the WAF
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Spread the returned middleware array
app.use(...createWAF());

app.get('/', (req, res) => res.json({ ok: true }));
app.listen(3000);
```

---

## Body parser ordering

`createWAF()` returns an **array** of middleware functions. The WAF inspects `req.body` for SQL injection, XSS, and other payloads. If body parsers run **after** the WAF, `req.body` is `undefined` when the WAF runs and POST/PUT body attacks will not be detected.

**Correct order:**
```js
app.use(express.json());                    // 1. parse body
app.use(express.urlencoded({ extended: true })); // 2. parse form body
app.use(...createWAF());                    // 3. inspect parsed body
app.use('/api', yourRouter);               // 4. application routes
```

**Wrong — WAF runs before body is parsed:**
```js
app.use(...createWAF());                    // body is undefined here
app.use(express.json());                    // too late
```

---

## Common mistakes

### Forgetting the spread operator

`createWAF()` returns an array. Without spreading, Express receives the array as a single argument instead of individual middleware functions:

```js
// Wrong — passes an array as one argument
app.use(createWAF());

// Correct — spreads the array into individual middleware
app.use(...createWAF());
```

### Mounting on a sub-path without spreading

```js
// Wrong
app.use('/api', createWAF());

// Correct
app.use('/api', ...createWAF());
```

### Using the default export pattern

The package uses named exports. There is no default export:

```js
// Wrong
const waf = require('firewtwall');
app.use(...waf());

// Correct
const { createWAF } = require('firewtwall');
app.use(...createWAF());
```

---

## With options

```js
app.use(...createWAF({
  mode: 'log-only',           // start in audit mode
  logPath: './logs/waf.log',
  debug: true,                // development only
}));
```

See [configuration.md](configuration.md) for every available option.

---

## TypeScript

Types ship with the package — no `@types/` install needed. See [typescript.md](typescript.md).
