'use strict';

const { logBlock } = require('../utils/logger');

/**
 * In-memory sliding-window rate limiter.
 *
 * For multi-process deployments swap the default MemoryStore with a
 * Redis-backed implementation exposing the same interface:
 *   { get(key), set(key, value), del(key) }
 *
 * Example Redis store:
 *   const { createRateLimitMiddleware, setStore } = require('./rateLimit');
 *   setStore(myRedisStore);
 */

class MemoryStore {
  constructor() {
    this._data = new Map();
  }

  get(key) { return this._data.get(key) ?? null; }
  set(key, value) { this._data.set(key, value); }
  del(key) { this._data.delete(key); }

  prune(windowMs) {
    const now = Date.now();
    for (const [key, entry] of this._data) {
      const expired = now > entry.windowStart + windowMs * 2;
      const unblocked = !entry.blockedUntil || now > entry.blockedUntil;
      if (expired && unblocked) this._data.delete(key);
    }
  }

  get size() { return this._data.size; }
}

// Module-level store — can be replaced via setStore()
let _store = new MemoryStore();
let _pruneTimer = null;

function startPruneTimer(windowMs) {
  if (_pruneTimer) return;
  _pruneTimer = setInterval(() => _store.prune(windowMs), 5 * 60 * 1000);
  _pruneTimer.unref?.();
}

/**
 * Replace the default in-memory store.
 * The replacement must implement: get(key), set(key, value), del(key).
 * @param {{ get: Function, set: Function, del: Function }} store
 */
function setStore(store) {
  _store = store;
  if (_pruneTimer) {
    clearInterval(_pruneTimer);
    _pruneTimer = null;
  }
}

function createRateLimitMiddleware(config) {
  const { windowMs, maxRequests, blockDurationMs } = config.rateLimit;
  startPruneTimer(windowMs);

  return function rateLimitMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    const ip = req.wafIp || req.socket?.remoteAddress || 'unknown';
    const now = Date.now();
    let entry = _store.get(ip);

    // Currently blocked
    if (entry?.blockedUntil && now < entry.blockedUntil) {
      const retryAfter = Math.ceil((entry.blockedUntil - now) / 1000);

      logBlock({
        logPath: config.logPath,
        ip,
        method: req.method,
        path: req.path,
        rule: 'rate-limit',
        severity: 'medium',
        userAgent: req.headers['user-agent'] || '',
      });

      if (config.mode === 'log-only') {
        res.set('X-RateLimit-Limit', String(maxRequests));
        res.set('X-RateLimit-Remaining', '0');
        return next();
      }

      res.set('Retry-After', String(retryAfter));
      return res.status(429).json({
        blocked: true,
        rule: 'rate-limit',
        message: 'Too many requests',
        retryAfter,
      });
    }

    // Slide window
    if (!entry || now - entry.windowStart >= windowMs) {
      entry = { count: 1, windowStart: now, blockedUntil: null };
    } else {
      entry.count += 1;
    }

    const remaining = Math.max(0, maxRequests - entry.count);
    const resetAt = Math.ceil((entry.windowStart + windowMs) / 1000);

    res.set('X-RateLimit-Limit', String(maxRequests));
    res.set('X-RateLimit-Remaining', String(remaining));
    res.set('X-RateLimit-Reset', String(resetAt));

    if (entry.count > maxRequests) {
      entry.blockedUntil = now + blockDurationMs;
      _store.set(ip, entry);

      logBlock({
        logPath: config.logPath,
        ip,
        method: req.method,
        path: req.path,
        rule: 'rate-limit-exceeded',
        severity: 'high',
        userAgent: req.headers['user-agent'] || '',
      });

      if (config.mode === 'log-only') return next();

      const retryAfter = Math.ceil(blockDurationMs / 1000);
      res.set('Retry-After', String(retryAfter));
      return res.status(429).json({
        blocked: true,
        rule: 'rate-limit-exceeded',
        message: 'Rate limit exceeded',
        retryAfter,
      });
    }

    _store.set(ip, entry);
    next();
  };
}

module.exports = { createRateLimitMiddleware, setStore };
