'use strict';

const { logBlock } = require('../utils/logger');

/**
 * Patterns that indicate prototype pollution attempts in key names or values.
 */
const POLLUTION_PATTERNS = [
  /^__proto__$/i,
  /constructor\.prototype/i,
  /\[.*prototype.*\]/i,
];

/**
 * URL-encoded variants of the dangerous key names.
 * These appear in raw query strings before they are parsed.
 */
const ENCODED_PATTERNS = [
  /%5F%5Fproto%5F%5F/i,           // __proto__
  /constructor%5Bprototype%5D/i,   // constructor[prototype]
  /%5B__proto__%5D/i,              // [__proto__]
  /__proto__/i,                    // plain (catches decoded too)
];

/**
 * Recursively walk every key of an object and test it against
 * POLLUTION_PATTERNS.
 *
 * @param {*}      input
 * @param {string} path  - Dot-notation path built during traversal (for logging)
 * @returns {string|null} The offending key path, or null
 */
function findPollutedKey(input, path) {
  if (!input || typeof input !== 'object') return null;

  for (const key of Object.keys(input)) {
    // Test the key itself
    for (const pat of POLLUTION_PATTERNS) {
      if (pat.test(key)) return path ? `${path}.${key}` : key;
    }
    // Recurse into nested objects / arrays
    const child = input[key];
    if (child && typeof child === 'object') {
      const result = findPollutedKey(child, path ? `${path}.${key}` : key);
      if (result) return result;
    }
  }
  return null;
}

/**
 * Middleware factory: detects prototype pollution attempts.
 *
 * Checks:
 *   1. Parsed JSON / form body — walks all nested keys
 *   2. Parsed query object   — walks all keys
 *   3. Raw query string      — scans for URL-encoded variants
 *
 * @param {object} config - Merged WAF configuration
 * @returns {Function} Express middleware
 */
function createPrototypePollutionMiddleware(config) {
  return function prototypePollutionMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    const ip = req.wafIp || req.socket?.remoteAddress || 'unknown';

    function handleHit(matched, source) {
      logBlock({
        logPath:   config.logPath,
        ip,
        method:    req.method,
        path:      req.path,
        rule:      'prototype-pollution',
        matched:   String(matched).slice(0, 120),
        source,
        severity:  'critical',
        userAgent: req.headers['user-agent'] || '',
      });

      if (config.mode === 'log-only') return false;

      res.status(403).json({
        blocked: true,
        rule:    'prototype-pollution',
        message: 'Request blocked by WAF',
      });
      return true;
    }

    // 1. Scan parsed body keys
    if (req.body && typeof req.body === 'object') {
      const hit = findPollutedKey(req.body, '');
      if (hit !== null) {
        if (handleHit(hit, 'body')) return;
      }
    }

    // 2. Scan parsed query keys
    if (req.query && typeof req.query === 'object') {
      const hit = findPollutedKey(req.query, '');
      if (hit !== null) {
        if (handleHit(hit, 'query')) return;
      }
    }

    // 3. Scan the raw query string for URL-encoded variants
    const rawQuery = req._parsedUrl?.query || req.url?.split('?')[1] || '';
    if (rawQuery) {
      for (const pat of ENCODED_PATTERNS) {
        const m = pat.exec(rawQuery);
        if (m) {
          if (handleHit(m[0], 'query:raw')) return;
        }
      }
    }

    next();
  };
}

module.exports = createPrototypePollutionMiddleware;
