'use strict';

const { logBlock } = require('../utils/logger');
const { deepDecode } = require('../utils/patternMatcher');

/**
 * Parameter names that typically carry URL-like values and are worth scanning
 * for SSRF payloads.
 */
const URL_PARAM_NAMES = new Set([
  'url', 'redirect', 'return', 'callback', 'next', 'dest', 'destination',
  'src', 'source', 'uri', 'link', 'href', 'proxy', 'forward',
]);

/**
 * Patterns for private / loopback IP ranges and cloud metadata endpoints.
 * Rule id: "ssrf-private-ip"
 */
const PRIVATE_IP_PATTERN = /(?:^|[/:@])(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|0\.0\.0\.0|::1\b|fd[0-9a-f]{2}:|fc[0-9a-f]{2}:)/i;

/**
 * Cloud instance metadata endpoints commonly abused in SSRF.
 * Rule id: "ssrf-cloud-metadata"
 */
const CLOUD_METADATA_PATTERN = /169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|100\.100\.100\.200/i;

/**
 * Dangerous URI schemes that should not appear in redirect/URL parameters.
 * Rule id: "ssrf-scheme"
 */
const DANGEROUS_SCHEME_PATTERN = /^(?:file|gopher|dict|ftp|ldap|tftp):\/\//i;

/**
 * Extract flat key→value pairs from a query-string object or body object,
 * keeping only the entries whose key is in URL_PARAM_NAMES.
 *
 * @param {object|undefined} obj
 * @returns {Array<{ key: string, value: string }>}
 */
function extractUrlParams(obj) {
  if (!obj || typeof obj !== 'object') return [];
  const results = [];
  for (const [key, raw] of Object.entries(obj)) {
    if (!URL_PARAM_NAMES.has(key.toLowerCase())) continue;
    const values = Array.isArray(raw) ? raw : [raw];
    for (const v of values) {
      if (typeof v === 'string') results.push({ key, value: v });
    }
  }
  return results;
}

/**
 * Scan a decoded value for SSRF indicators.
 * Returns the matching rule id or null.
 *
 * @param {string} decoded
 * @returns {string|null}
 */
function detectSsrf(decoded) {
  if (DANGEROUS_SCHEME_PATTERN.test(decoded)) return 'ssrf-scheme';
  if (CLOUD_METADATA_PATTERN.test(decoded))   return 'ssrf-cloud-metadata';
  if (PRIVATE_IP_PATTERN.test(decoded))       return 'ssrf-private-ip';
  return null;
}

/**
 * Middleware factory: detects Server-Side Request Forgery attempts.
 *
 * Scans URL-suggestive query params, body fields, and all header values
 * for private IP ranges, cloud metadata addresses, and dangerous URI schemes.
 *
 * @param {object} config - Merged WAF configuration
 * @returns {Function} Express middleware
 */
function createSsrfMiddleware(config) {
  return function ssrfMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    const ip = req.wafIp || req.socket?.remoteAddress || 'unknown';

    /**
     * Helper: log and optionally block when a hit is found.
     * @param {string} ruleId
     * @param {string} matched
     * @param {string} source
     * @returns {boolean} true if the request was blocked (response sent)
     */
    function handleHit(ruleId, matched, source) {
      logBlock({
        logPath:   config.logPath,
        ip,
        method:    req.method,
        path:      req.path,
        rule:      ruleId,
        matched:   matched.slice(0, 120),
        source,
        severity:  'critical',
        userAgent: req.headers['user-agent'] || '',
      });

      if (config.mode === 'log-only') return false;

      res.status(403).json({
        blocked: true,
        rule:    ruleId,
        message: 'Request blocked by WAF',
      });
      return true;
    }

    // --- 1. Scan query params ---
    for (const { key, value } of extractUrlParams(req.query)) {
      const decoded = deepDecode(value);
      const rule = detectSsrf(decoded);
      if (rule) {
        if (handleHit(rule, decoded, `query:${key}`)) return;
      }
    }

    // --- 2. Scan body fields (parsed JSON / urlencoded) ---
    if (req.body && typeof req.body === 'object') {
      for (const { key, value } of extractUrlParams(req.body)) {
        const decoded = deepDecode(value);
        const rule = detectSsrf(decoded);
        if (rule) {
          if (handleHit(rule, decoded, `body:${key}`)) return;
        }
      }
    }

    // --- 3. Scan all header values for SSRF indicators ---
    // Headers can carry injected URLs via X-Forwarded-*, Referer, Origin, etc.
    for (const [headerName, headerValue] of Object.entries(req.headers)) {
      const decoded = deepDecode(String(headerValue));
      const rule = detectSsrf(decoded);
      if (rule) {
        if (handleHit(rule, decoded, `header:${headerName}`)) return;
      }
    }

    next();
  };
}

module.exports = createSsrfMiddleware;
