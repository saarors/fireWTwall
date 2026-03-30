# Redis / Multi-Process Rate Limiting

## Why you need it

The default in-memory rate-limit store is per-process. If you run multiple Node.js processes — PM2 cluster mode, Docker replicas, or multiple servers — each process maintains its own counter. An attacker can send 100 requests to each of 4 workers (400 total) and never trigger the limit.

Replace the store with Redis to share counters across all processes.

---

## setStore() API

```js
const { setStore } = require('firewtwall');

setStore({
  get: async (key) => { /* return value or null */ },
  set: async (key, value) => { /* store value */ },
  del: async (key) => { /* delete key */ },
});
```

Call `setStore()` before mounting the WAF middleware. The store is global — one call configures it for all `createWAF()` instances in the process.

---

## ioredis example

```js
const express = require('express');
const { createWAF, setStore } = require('firewtwall');
const Redis = require('ioredis');

const redis = new Redis({
  host: process.env.REDIS_HOST || '127.0.0.1',
  port: 6379,
});

setStore({
  get: async (key) => {
    const val = await redis.get(key);
    return val ? JSON.parse(val) : null;
  },
  set: async (key, value) => {
    // Rate-limit entries include a TTL field — honor it
    const ttlMs = value.resetAt ? value.resetAt - Date.now() : 600_000;
    const ttlSec = Math.max(1, Math.ceil(ttlMs / 1000));
    await redis.set(key, JSON.stringify(value), 'EX', ttlSec);
  },
  del: async (key) => {
    await redis.del(key);
  },
});

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(...createWAF({ rateLimit: { maxRequests: 100, windowMs: 60_000 } }));
app.listen(3000);
```

---

## node-redis (v4) example

```js
const { createClient } = require('redis');
const { setStore } = require('firewtwall');

const redis = createClient({ url: process.env.REDIS_URL || 'redis://localhost:6379' });
await redis.connect();

setStore({
  get: async (key) => {
    const val = await redis.get(key);
    return val ? JSON.parse(val) : null;
  },
  set: async (key, value) => {
    const ttlMs = value.resetAt ? value.resetAt - Date.now() : 600_000;
    const ttlSec = Math.max(1, Math.ceil(ttlMs / 1000));
    await redis.set(key, JSON.stringify(value), { EX: ttlSec });
  },
  del: async (key) => {
    await redis.del(key);
  },
});
```

---

## Custom store interface

Any object with the following three async methods works:

```ts
interface StoreAdapter {
  get(key: string): Promise<any>;
  set(key: string, value: any): Promise<void>;
  del(key: string): Promise<void>;
}
```

**Key format:** `waf:rl:<ip>` for rate-limit entries, `waf:block:<ip>` for active blocks.

**Value shape** stored by the rate limiter:

```json
{
  "count": 47,
  "windowStart": 1711801200000,
  "resetAt": 1711801260000
}
```

If you use a store that supports TTL natively (Redis, Memcached), set the TTL to `Math.ceil((value.resetAt - Date.now()) / 1000)` seconds so stale entries expire automatically.

---

## Memcached example

```js
const Memcached = require('memcached');
const mem = new Memcached('localhost:11211');
const { setStore } = require('firewtwall');

function memGet(key) {
  return new Promise((res, rej) =>
    mem.get(key, (err, data) => err ? rej(err) : res(data ?? null))
  );
}
function memSet(key, value) {
  const ttlSec = Math.max(1, Math.ceil((value.resetAt - Date.now()) / 1000));
  return new Promise((res, rej) =>
    mem.set(key, value, ttlSec, (err) => err ? rej(err) : res())
  );
}
function memDel(key) {
  return new Promise((res, rej) =>
    mem.del(key, (err) => err ? rej(err) : res())
  );
}

setStore({ get: memGet, set: memSet, del: memDel });
```

---

## Notes

- `setStore()` is global and affects all `createWAF()` instances in the process.
- The WAF only uses the store for rate limiting. IP filtering, rule matching, and logging are not affected by the store.
- In a single-process deployment the default in-memory store is sufficient.
