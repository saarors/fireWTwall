'use strict';

const { extractIp } = require('../utils/ipUtils');
const { logBlock }  = require('../utils/logger');

// ---------------------------------------------------------------------------
// In-memory stores (per-process; swap with Redis adapters for multi-node)
// ---------------------------------------------------------------------------

/** Per-IP burst store: Map<ip, { count, windowStart, blockedUntil, blockCount }> */
const burstStore = new Map();

/** Per-fingerprint store: Map<fp, { count, windowStart, blockedUntil }> */
const fpStore = new Map();

/** Per-path store: Map<path, { count, windowStart }> */
const pathStore = new Map();

/** Global counter: { count, windowStart } */
const globalCounter = { count: 0, windowStart: Date.now() };

// ---------------------------------------------------------------------------
// Memory cleanup — runs every 60 seconds
// ---------------------------------------------------------------------------
const _cleanupTimer = setInterval(() => {
  const now = Date.now();

  for (const [key, entry] of burstStore) {
    const expired   = now > entry.windowStart + 120_000;
    const unblocked = !entry.blockedUntil || now > entry.blockedUntil;
    if (expired && unblocked) burstStore.delete(key);
  }

  for (const [key, entry] of fpStore) {
    const expired   = now > entry.windowStart + 120_000;
    const unblocked = !entry.blockedUntil || now > entry.blockedUntil;
    if (expired && unblocked) fpStore.delete(key);
  }

  for (const [key, entry] of pathStore) {
    if (now > entry.windowStart + 60_000) pathStore.delete(key);
  }

  // Reset global counter if its window has expired
  // (it self-resets on each request; this just clears stale state)
  if (now > globalCounter.windowStart + 60_000) {
    globalCounter.count       = 0;
    globalCounter.windowStart = now;
  }
}, 60_000);

// Allow the Node.js process to exit normally even if this timer is active.
_cleanupTimer.unref?.();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Send a block response or pass through in log-only mode.
 *
 * @param {object}   opts
 * @param {object}   opts.config
 * @param {object}   opts.req
 * @param {object}   opts.res
 * @param {Function} opts.next
 * @param {string}   opts.ip
 * @param {string}   opts.rule
 * @param {string}   opts.severity
 * @param {number}   opts.status        HTTP status code
 * @param {string}   opts.message       Human-readable message
 * @param {number}   [opts.retryAfter]  Seconds for Retry-After header
 * @returns {boolean}  true if the request was blocked (caller should return)
 */
function block(opts) {
  const { config, req, res, next, ip, rule, severity, status, message } = opts;

  logBlock({
    logPath:   config.logPath,
    requestId: res.wafRequestId,
    ip,
    method:    req.method,
    path:      req.path,
    rule,
    severity,
    source:    'ddos',
    userAgent: req.headers['user-agent'] || '',
  });

  if (config.mode === 'log-only') {
    next();
    return true; // "handled" — caller must return
  }

  if (status === 429) res.set('Retry-After', '60');
  if (status === 503) res.set('Retry-After', '5');

  res.status(status).json({
    blocked: true,
    rule,
    message,
  });

  return true;
}

// ---------------------------------------------------------------------------
// Middleware factory
// ---------------------------------------------------------------------------

/**
 * Creates the DDoS protection middleware.
 *
 * @param {object} config - Merged WAF configuration
 * @returns {Function} Express middleware
 */
module.exports = function createDdosMiddleware(config) {
  const ddosCfg = config.ddos || {};

  // Resolved limits (fall back to spec defaults if config is partial)
  const maxUrlLength    = ddosCfg.maxUrlLength    ?? 2048;
  const maxHeaderCount  = ddosCfg.maxHeaderCount  ?? 100;
  const maxHeaderSize   = ddosCfg.maxHeaderSize   ?? 8192;

  const burst = {
    windowMs:        ddosCfg.burst?.windowMs        ?? 1_000,
    maxRequests:     ddosCfg.burst?.maxRequests      ?? 20,
    blockDurationMs: ddosCfg.burst?.blockDurationMs  ?? 60_000,
  };

  const global_ = {
    windowMs:    ddosCfg.global?.windowMs    ?? 1_000,
    maxRequests: ddosCfg.global?.maxRequests ?? 500,
  };

  const fingerprint = {
    windowMs:        ddosCfg.fingerprint?.windowMs        ?? 10_000,
    maxRequests:     ddosCfg.fingerprint?.maxRequests      ?? 50,
    blockDurationMs: ddosCfg.fingerprint?.blockDurationMs  ?? 60_000,
  };

  const pathFlood = {
    windowMs:    ddosCfg.pathFlood?.windowMs    ?? 5_000,
    maxRequests: ddosCfg.pathFlood?.maxRequests ?? 200,
  };

  const tarpit = {
    enabled: ddosCfg.tarpit?.enabled ?? false,
    delayMs: ddosCfg.tarpit?.delayMs ?? 2_000,
  };

  // -------------------------------------------------------------------------
  return function ddos(req, res, next) {
    // Trusted IPs bypass DDoS checks (already whitelisted upstream)
    if (req.wafTrusted) return next();

    const ip  = req.wafIp || extractIp(req, config.trustedProxies || []);
    const now = Date.now();

    // ------------------------------------------------------------------
    // Layer 1 — URL length guard
    // ------------------------------------------------------------------
    if (req.url.length > maxUrlLength) {
      return block({
        config, req, res, next, ip,
        rule:     'ddos-url-length',
        severity: 'high',
        status:   414,
        message:  'URI Too Long',
      }) && undefined;
    }

    // ------------------------------------------------------------------
    // Layer 2 — Header count guard
    // ------------------------------------------------------------------
    if (Object.keys(req.headers).length > maxHeaderCount) {
      return block({
        config, req, res, next, ip,
        rule:     'ddos-header-count',
        severity: 'high',
        status:   431,
        message:  'Too many request headers',
      }) && undefined;
    }

    // ------------------------------------------------------------------
    // Layer 3 — Header size guard
    // ------------------------------------------------------------------
    for (const value of Object.values(req.headers)) {
      if (typeof value === 'string' && value.length > maxHeaderSize) {
        return block({
          config, req, res, next, ip,
          rule:     'ddos-header-size',
          severity: 'high',
          status:   431,
          message:  'Request header field too large',
        }) && undefined;
      }
    }

    // ------------------------------------------------------------------
    // Layer 4 — Burst rate limiter (per-IP, 1-second window)
    // ------------------------------------------------------------------
    {
      let bEntry = burstStore.get(ip);

      // Check active block first
      if (bEntry?.blockedUntil && now < bEntry.blockedUntil) {
        // Tarpitting: delay repeat offenders before responding
        if (tarpit.enabled && bEntry.blockCount > 3) {
          const respond = () =>
            block({
              config, req, res, next, ip,
              rule:     'ddos-burst',
              severity: 'high',
              status:   429,
              message:  'Burst rate limit exceeded',
            });

          return void setTimeout(respond, tarpit.delayMs);
        }

        return block({
          config, req, res, next, ip,
          rule:     'ddos-burst',
          severity: 'high',
          status:   429,
          message:  'Burst rate limit exceeded',
        }) && undefined;
      }

      // Slide window
      if (!bEntry || now - bEntry.windowStart >= burst.windowMs) {
        bEntry = { count: 1, windowStart: now, blockedUntil: null, blockCount: bEntry?.blockCount ?? 0 };
      } else {
        bEntry.count += 1;
      }

      if (bEntry.count > burst.maxRequests) {
        bEntry.blockedUntil = now + burst.blockDurationMs;
        bEntry.blockCount   = (bEntry.blockCount || 0) + 1;
        burstStore.set(ip, bEntry);

        return block({
          config, req, res, next, ip,
          rule:     'ddos-burst',
          severity: 'high',
          status:   429,
          message:  'Burst rate limit exceeded',
        }) && undefined;
      }

      burstStore.set(ip, bEntry);
    }

    // ------------------------------------------------------------------
    // Layer 5 — Global rate limiter (all IPs combined)
    // ------------------------------------------------------------------
    {
      if (now - globalCounter.windowStart >= global_.windowMs) {
        globalCounter.count       = 0;
        globalCounter.windowStart = now;
      }
      globalCounter.count += 1;

      if (globalCounter.count > global_.maxRequests) {
        return block({
          config, req, res, next, ip,
          rule:     'ddos-global-flood',
          severity: 'critical',
          status:   503,
          message:  'Service temporarily unavailable',
        }) && undefined;
      }
    }

    // ------------------------------------------------------------------
    // Layer 6 — Request fingerprint flood detection
    // ------------------------------------------------------------------
    {
      const ua  = req.headers['user-agent'] || '';
      const fpKey = `${ip}\x00${ua}\x00${req.path}`;

      let fpEntry = fpStore.get(fpKey);

      // Check active block
      if (fpEntry?.blockedUntil && now < fpEntry.blockedUntil) {
        return block({
          config, req, res, next, ip,
          rule:     'ddos-fingerprint-flood',
          severity: 'high',
          status:   429,
          message:  'Request fingerprint flood detected',
        }) && undefined;
      }

      // Slide window
      if (!fpEntry || now - fpEntry.windowStart >= fingerprint.windowMs) {
        fpEntry = { count: 1, windowStart: now, blockedUntil: null };
      } else {
        fpEntry.count += 1;
      }

      if (fpEntry.count > fingerprint.maxRequests) {
        fpEntry.blockedUntil = now + fingerprint.blockDurationMs;
        fpStore.set(fpKey, fpEntry);

        return block({
          config, req, res, next, ip,
          rule:     'ddos-fingerprint-flood',
          severity: 'high',
          status:   429,
          message:  'Request fingerprint flood detected',
        }) && undefined;
      }

      fpStore.set(fpKey, fpEntry);
    }

    // ------------------------------------------------------------------
    // Layer 7 — Repeated path flood (cross-IP, same endpoint)
    // ------------------------------------------------------------------
    {
      let pEntry = pathStore.get(req.path);

      if (!pEntry || now - pEntry.windowStart >= pathFlood.windowMs) {
        pEntry = { count: 1, windowStart: now };
      } else {
        pEntry.count += 1;
      }

      pathStore.set(req.path, pEntry);

      if (pEntry.count > pathFlood.maxRequests) {
        return block({
          config, req, res, next, ip,
          rule:     'ddos-path-flood',
          severity: 'critical',
          status:   503,
          message:  'Service temporarily unavailable',
        }) && undefined;
      }
    }

    // All DDoS layers passed
    next();
  };
};
