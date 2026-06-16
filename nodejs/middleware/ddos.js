'use strict';

const { extractIp } = require('../utils/ipUtils');
const { logBlock } = require('../utils/logger');

// -----------------------------------------------------
// Simple LRU helper (no dependency)
// -----------------------------------------------------
class LRU {
  constructor(limit = 5000) {
    this.limit = limit;
    this.map = new Map();
  }

  get(key) {
    const val = this.map.get(key);
    if (!val) return null;
    this.map.delete(key);
    this.map.set(key, val);
    return val;
  }

  set(key, value) {
    if (this.map.has(key)) this.map.delete(key);
    this.map.set(key, value);

    if (this.map.size > this.limit) {
      const firstKey = this.map.keys().next().value;
      this.map.delete(firstKey);
    }
  }

  delete(key) {
    this.map.delete(key);
  }
}

// -----------------------------------------------------
// Stores
// -----------------------------------------------------
const burstStore = new Map();        // per-IP
const fpStore = new Map();           // fingerprint
const pathStore = new LRU(5000);     // prevent memory explosion

const globalCounter = {
  count: 0,
  windowStart: Date.now(),
};

// -----------------------------------------------------
// Cleanup
// -----------------------------------------------------
setInterval(() => {
  const now = Date.now();

  for (const [k, v] of burstStore) {
    if (v.blockedUntil && now < v.blockedUntil) continue;
    if (now - v.windowStart > 120_000) burstStore.delete(k);
  }

  for (const [k, v] of fpStore) {
    if (v.blockedUntil && now < v.blockedUntil) continue;
    if (now - v.windowStart > 120_000) fpStore.delete(k);
  }

  if (now - globalCounter.windowStart > 60_000) {
    globalCounter.count = 0;
    globalCounter.windowStart = now;
  }
}, 60_000).unref?.();

// -----------------------------------------------------
// Block helper
// -----------------------------------------------------
function block({ config, req, res, next, ip, rule, severity, status, message }) {
  logBlock({
    logPath: config.logPath,
    requestId: res.wafRequestId,
    ip,
    method: req.method,
    path: req.path,
    rule,
    severity,
    source: 'ddos',
    userAgent: req.headers['user-agent'] || '',
  });

  if (config.mode === 'log-only') {
    return next(), true;
  }

  const retryAfter = status === 429 ? '60' : status === 503 ? '5' : undefined;
  if (retryAfter) res.set('Retry-After', retryAfter);

  res.status(status).json({
    blocked: true,
    rule,
    message,
  });

  return true;
}

// -----------------------------------------------------
// Middleware
// -----------------------------------------------------
module.exports = function createDdosMiddleware(config) {
  const ddos = config.ddos || {};

  const maxUrlLength = ddos.maxUrlLength ?? 2048;
  const maxHeaderCount = ddos.maxHeaderCount ?? 100;
  const maxHeaderSize = ddos.maxHeaderSize ?? 8192;

  const burst = {
    windowMs: ddos.burst?.windowMs ?? 1000,
    maxRequests: ddos.burst?.maxRequests ?? 20,
    blockDurationMs: ddos.burst?.blockDurationMs ?? 60000,
  };

  const fingerprint = {
    windowMs: ddos.fingerprint?.windowMs ?? 10000,
    maxRequests: ddos.fingerprint?.maxRequests ?? 50,
    blockDurationMs: ddos.fingerprint?.blockDurationMs ?? 60000,
  };

  const pathFlood = {
    windowMs: ddos.pathFlood?.windowMs ?? 5000,
    maxRequests: ddos.pathFlood?.maxRequests ?? 200,
  };

  const tarpit = {
    enabled: ddos.tarpit?.enabled ?? false,
    delayMs: ddos.tarpit?.delayMs ?? 2000,
  };

  return function ddos(req, res, next) {
    if (req.wafTrusted) return next();

    const ip = req.wafIp || extractIp(req, config.trustedProxies || []);
    const now = Date.now();

    const rawUrl = req.originalUrl || req.url;

    // normalize path (remove query)
    const path = req.path || rawUrl.split('?')[0];

    // -------------------------------------------------
    // 1. URL length
    // -------------------------------------------------
    if (rawUrl.length > maxUrlLength) {
      return block({
        config, req, res, next, ip,
        rule: 'ddos-url-length',
        severity: 'high',
        status: 414,
        message: 'URI Too Long',
      }) && undefined;
    }

    // -------------------------------------------------
    // 2. Header count
    // -------------------------------------------------
    if (Object.keys(req.headers).length > maxHeaderCount) {
      return block({
        config, req, res, next, ip,
        rule: 'ddos-header-count',
        severity: 'high',
        status: 431,
        message: 'Too many headers',
      }) && undefined;
    }

    // -------------------------------------------------
    // 3. Header size (bytes correct)
    // -------------------------------------------------
    for (const v of Object.values(req.headers)) {
      if (!v) continue;

      const size = Buffer.byteLength(
        Array.isArray(v) ? v.join(',') : String(v),
        'utf8'
      );

      if (size > maxHeaderSize) {
        return block({
          config, req, res, next, ip,
          rule: 'ddos-header-size',
          severity: 'high',
          status: 431,
          message: 'Header too large',
        }) && undefined;
      }
    }

    // -------------------------------------------------
    // 4. Burst per IP (sliding window)
    // -------------------------------------------------
    let b = burstStore.get(ip);

    if (b?.blockedUntil && now < b.blockedUntil) {
      if (tarpit.enabled) {
        return setTimeout(() => {
          block({
            config, req, res, next, ip,
            rule: 'ddos-burst',
            severity: 'high',
            status: 429,
            message: 'Burst limit exceeded',
          });
        }, tarpit.delayMs);
      }

      return block({
        config, req, res, next, ip,
        rule: 'ddos-burst',
        severity: 'high',
        status: 429,
        message: 'Burst limit exceeded',
      }) && undefined;
    }

    if (!b || now - b.windowStart > burst.windowMs) {
      b = { count: 1, windowStart: now, blockedUntil: null, blockCount: b?.blockCount ?? 0 };
    } else {
      b.count++;
    }

    if (b.count > burst.maxRequests) {
      b.blockedUntil = now + burst.blockDurationMs;
      b.blockCount++;
      burstStore.set(ip, b);

      return block({
        config, req, res, next, ip,
        rule: 'ddos-burst',
        severity: 'high',
        status: 429,
        message: 'Burst limit exceeded',
      }) && undefined;
    }

    burstStore.set(ip, b);

    // -------------------------------------------------
    // 5. Global rate limit
    // -------------------------------------------------
    if (now - globalCounter.windowStart > 60000) {
      globalCounter.count = 0;
      globalCounter.windowStart = now;
    }

    if (++globalCounter.count > (ddos.global?.maxRequests ?? 500)) {
      return block({
        config, req, res, next, ip,
        rule: 'ddos-global',
        severity: 'critical',
        status: 503,
        message: 'Service overloaded',
      }) && undefined;
    }

    // -------------------------------------------------
    // 6. Fingerprint
    // -------------------------------------------------
    const ua = req.headers['user-agent'] || '';
    const accept = req.headers['accept'] || '';

    const fp = `${ip}|${ua}|${accept}|${path}`;
    let f = fpStore.get(fp);

    if (f?.blockedUntil && now < f.blockedUntil) {
      return block({
        config, req, res, next, ip,
        rule: 'ddos-fingerprint',
        severity: 'high',
        status: 429,
        message: 'Fingerprint flood detected',
      }) && undefined;
    }

    if (!f || now - f.windowStart > fingerprint.windowMs) {
      f = { count: 1, windowStart: now, blockedUntil: null };
    } else {
      f.count++;
    }

    if (f.count > fingerprint.maxRequests) {
      f.blockedUntil = now + fingerprint.blockDurationMs;
      fpStore.set(fp, f);

      return block({
        config, req, res, next, ip,
        rule: 'ddos-fingerprint',
        severity: 'high',
        status: 429,
        message: 'Fingerprint flood detected',
      }) && undefined;
    }

    fpStore.set(fp, f);

    // -------------------------------------------------
    // 7. Path flood (LRU protected)
    // -------------------------------------------------
    let p = pathStore.get(path);

    if (!p || now - p.windowStart > pathFlood.windowMs) {
      p = { count: 1, windowStart: now };
    } else {
      p.count++;
    }

    pathStore.set(path, p);

    if (p.count > pathFlood.maxRequests) {
      return block({
        config, req, res, next, ip,
        rule: 'ddos-path',
        severity: 'critical',
        status: 503,
        message: 'Path flood detected',
      }) && undefined;
    }

    next();
  };
};
