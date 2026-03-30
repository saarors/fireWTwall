# TypeScript Usage

TypeScript types ship with the `firewtwall` package. No `@types/` install is needed.

```bash
npm install firewtwall
# types are included — no @types/firewtwall needed
```

---

## Exported types

### WAFOptions

Full configuration object passed to `createWAF()`.

```ts
interface WAFOptions {
  mode?: 'reject' | 'log-only';
  allowedMethods?: string[];
  maxBodySize?: number;
  rateLimit?: RateLimitOptions;
  whitelist?: string[];
  blacklist?: string[];
  bypassPaths?: string[];
  trustedProxies?: string[];
  logPath?: string;
  responseType?: 'json' | 'html';
  debug?: boolean;
}
```

### RateLimitOptions

```ts
interface RateLimitOptions {
  windowMs?: number;
  maxRequests?: number;
  blockDurationMs?: number;
}
```

### StoreAdapter

Interface for custom rate-limit stores (Redis, Memcached, etc.).

```ts
interface StoreAdapter {
  get(key: string): Promise<any>;
  set(key: string, value: any): Promise<void>;
  del(key: string): Promise<void>;
}
```

---

## Full annotated example

```ts
import express, { Application } from 'express';
import { createWAF, setStore, WAFOptions, StoreAdapter } from 'firewtwall';
import Redis from 'ioredis';

// ── Redis store (type-safe) ──────────────────────────────────────────────────

const redis = new Redis();

const redisStore: StoreAdapter = {
  get: async (key: string) => {
    const val = await redis.get(key);
    return val ? JSON.parse(val) : null;
  },
  set: async (key: string, value: unknown) => {
    const ttlSec = 660; // slightly over max block duration
    await redis.set(key, JSON.stringify(value), 'EX', ttlSec);
  },
  del: async (key: string) => {
    await redis.del(key);
  },
};

setStore(redisStore);

// ── WAF configuration ────────────────────────────────────────────────────────

const wafOptions: WAFOptions = {
  mode: 'reject',
  debug: false,
  rateLimit: {
    windowMs: 60_000,
    maxRequests: 100,
    blockDurationMs: 600_000,
  },
  whitelist: ['127.0.0.1', '10.0.0.0/8'],
  blacklist: ['203.0.113.0/24'],
  bypassPaths: ['/health', '/ping'],
  trustedProxies: ['172.16.0.1'],
  logPath: './logs/waf.log',
  responseType: 'json',
};

// ── Application ──────────────────────────────────────────────────────────────

const app: Application = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(...createWAF(wafOptions));

app.get('/', (_req, res) => {
  res.json({ ok: true });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

---

## Using mode as a union type

```ts
import { WAFOptions } from 'firewtwall';

function buildWafOptions(env: string): WAFOptions {
  return {
    mode: env === 'production' ? 'reject' : 'log-only',
    debug: env !== 'production',
  };
}
```

---

## Extending types

If you need to augment the Express request object (e.g. to access `req.wafRequestId` added in debug mode), declare a module augmentation:

```ts
// types/express.d.ts
declare namespace Express {
  interface Request {
    wafRequestId?: string;
    wafTrusted?: boolean;
    wafIp?: string;
  }
}
```

---

## tsconfig note

The package ships CommonJS (`.js`) with declaration files (`.d.ts`). It works with both `"module": "commonjs"` and `"module": "esnext"` in your `tsconfig.json`. With ESM output in TypeScript, import as:

```ts
import { createWAF } from 'firewtwall';
```
