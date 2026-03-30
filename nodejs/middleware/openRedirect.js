'use strict';

const { logBlock } = require('../utils/logger');
const { deepDecode } = require('../utils/patternMatcher');

/**
 * Parameter names that are commonly used to carry redirect destinations.
 * Matching is case-insensitive.
 */
const REDIRECT_PARAM_NAMES = new Set([
  'redirect', 'return', 'returnurl', 'next', 'url', 'dest', 'destination',
  'go', 'goto', 'target', 'redir', 'r', 'u', 'link', 'forward',
  'location', 'continue', 'ref',
]);

/**
 * Determine whether a decoded redirect value is an open-redirect attempt.
 *
 * Rules:
 *   - Block absolute http:// or https:// URLs
 *   - Block protocol-relative URLs starting with //
 *   - Block Windows UNC paths starting with \\
 *   - Block paths like /\evil.com (slash-backslash bypass)
 *   - Allow plain relative paths starting with / (but NOT //)
 *
 * @param {string} value - Already URL-decoded value
 * @returns {boolean}
 */
function isOpenRedirect(value) {
  const v = value.trimStart();

  // Absolute URL with scheme
  if (/^https?:\/\//i.test(v)) return true;

  // Protocol-relative: //anything
  if (/^\/\//.test(v)) return true;

  // Windows UNC or backslash escape: \\server or /\server
  if (/^\\\\/.test(v) || /^\/\\/.test(v)) return true;

  return false;
}

/**
 * Middleware factory: detects open-redirect attempts in URL-bearing parameters.
 *
 * @param {object} config - Merged WAF configuration
 * @returns {Function} Express middleware
 */
function createOpenRedirectMiddleware(config) {
  return function openRedirectMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    const ip = req.wafIp || req.socket?.remoteAddress || 'unknown';

    /**
     * Scan a flat object (query or body) for open-redirect values.
     * @param {object} obj
     * @param {string} sourceLabel  e.g. 'query' or 'body'
     * @returns {boolean} true if the request was blocked
     */
    function scanObject(obj, sourceLabel) {
      if (!obj || typeof obj !== 'object') return false;

      for (const [key, raw] of Object.entries(obj)) {
        if (!REDIRECT_PARAM_NAMES.has(key.toLowerCase())) continue;

        const values = Array.isArray(raw) ? raw : [raw];
        for (const v of values) {
          if (typeof v !== 'string') continue;

          const decoded = deepDecode(v);
          if (!isOpenRedirect(decoded)) continue;

          logBlock({
            logPath:   config.logPath,
            ip,
            method:    req.method,
            path:      req.path,
            rule:      'open-redirect',
            matched:   decoded.slice(0, 120),
            source:    `${sourceLabel}:${key}`,
            severity:  'high',
            userAgent: req.headers['user-agent'] || '',
          });

          if (config.mode === 'log-only') return false; // log and continue
          res.status(403).json({
            blocked: true,
            rule:    'open-redirect',
            message: 'Request blocked by WAF',
          });
          return true; // blocked
        }
      }
      return false;
    }

    if (scanObject(req.query, 'query')) return;
    if (req.body && typeof req.body === 'object') {
      if (scanObject(req.body, 'body')) return;
    }

    next();
  };
}

module.exports = createOpenRedirectMiddleware;
