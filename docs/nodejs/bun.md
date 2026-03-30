# Bun Runtime Support

fireWTwall fully supports [Bun](https://bun.sh/) — a fast JavaScript runtime and package manager compatible with Node.js.

---

## Installation

```bash
bun add firewtwall
```

---

## Quick Start

Bun is compatible with Node.js CommonJS and ES modules. Use fireWTwall the same way as with Node.js:

```js
import { createWAF } from 'firewtwall';
import express from 'express';

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(...createWAF());

app.get('/', (req, res) => res.json({ ok: true }));
app.listen(3000);
```

Or with CommonJS:

```js
const express = require('express');
const { createWAF } = require('firewtwall');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(...createWAF());

app.get('/', (req, res) => res.json({ ok: true }));
app.listen(3000);
```

---

## Running with Bun

```bash
# Start the example server
bun example/server.js

# Or with npm script
bun run example:bun
```

---

## Configuration

All fireWTwall configuration options work identically with Bun. See [configuration.md](configuration.md) for the full reference.

```js
app.use(...createWAF({
  mode: 'log-only',
  logPath: './logs/waf.log',
  debug: true,
}));
```

---

## Performance

Bun's performance characteristics make it ideal for WAF workloads:

- **Faster startup** — Bun starts faster than Node.js
- **Better I/O** — Native SQLite, faster file operations
- **Lower memory** — More efficient runtime
- **Same protection** — Identical security rules and detection logic

---

## TypeScript

Bun has excellent TypeScript support out of the box. No build step needed:

```ts
import { createWAF, WAFConfig } from 'firewtwall';

const config: WAFConfig = {
  mode: 'block',
  logPath: './logs/waf.log',
};

app.use(...createWAF(config));
```

---

## Limitations

- None — fireWTwall is fully compatible with Bun
- All Node.js APIs used by fireWTwall are supported in Bun >= 1.0.0

---

## Troubleshooting

### Import errors

If you encounter import issues, ensure your `bunfig.toml` includes:

```toml
[install]
optional = true
```

This allows optional peer dependencies to be installed correctly.

### Express compatibility

Bun is fully compatible with Express. If you encounter issues, ensure you're running Bun >= 1.0.0:

```bash
bun --version
```

---

## See also

- [Bun documentation](https://bun.sh/docs)
- [Installation guide](installation.md)
- [Configuration reference](configuration.md)
