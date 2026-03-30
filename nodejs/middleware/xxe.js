'use strict';

const { logBlock } = require('../utils/logger');

/**
 * XXE detection rules applied to the raw request body when the content type
 * indicates XML or the body itself begins with an XML declaration / DOCTYPE.
 */
const XXE_RULES = [
  {
    id:          'xxe-external-entity',
    pattern:     /<!ENTITY\s+\w+\s+SYSTEM/i,
    severity:    'critical',
    description: 'XML external entity declaration',
  },
  {
    id:          'xxe-parameter-entity',
    pattern:     /<!ENTITY\s+%/i,
    severity:    'critical',
    description: 'XML parameter entity declaration',
  },
  {
    id:          'xxe-system-id',
    pattern:     /SYSTEM\s+["']/i,
    severity:    'critical',
    description: 'SYSTEM identifier in XML',
  },
  {
    id:          'xxe-public-id',
    pattern:     /PUBLIC\s+["']/i,
    severity:    'critical',
    description: 'PUBLIC identifier in XML',
  },
  {
    id:          'xxe-xinclude',
    pattern:     /<xi:include/i,
    severity:    'critical',
    description: 'XInclude directive',
  },
  // DOCTYPE with inline subset is a prerequisite for most XXE; flag it too.
  {
    id:          'xxe-doctype-entity',
    pattern:     /<!DOCTYPE[^>]*\[/i,
    severity:    'critical',
    description: 'DOCTYPE with inline entity subset',
  },
];

/**
 * Determine whether the request body should be scanned for XXE.
 * Only scan when the content type is XML or the body starts with typical
 * XML preambles.
 *
 * @param {object} req - Express request
 * @returns {boolean}
 */
function isXmlRequest(req) {
  const ct = (req.headers['content-type'] || '').toLowerCase();
  if (ct.includes('xml')) return true;

  // Fall back to body content inspection
  const raw = req.rawBody || (typeof req.body === 'string' ? req.body : '');
  if (typeof raw === 'string') {
    const trimmed = raw.trimStart();
    if (trimmed.startsWith('<?xml') || trimmed.startsWith('<!DOCTYPE')) return true;
  }

  return false;
}

/**
 * Middleware factory: detects XML External Entity (XXE) injection.
 *
 * Requires body-parser (or equivalent) to populate req.body.
 * For raw body access, frameworks like express-xml-bodyparser or a custom
 * rawBody middleware should populate req.rawBody.
 *
 * @param {object} config - Merged WAF configuration
 * @returns {Function} Express middleware
 */
function createXxeMiddleware(config) {
  return function xxeMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    // Only inspect XML content
    if (!isXmlRequest(req)) return next();

    // Prefer the raw unparsed body string for accurate pattern matching
    let bodyStr = req.rawBody || '';
    if (!bodyStr && typeof req.body === 'string') {
      bodyStr = req.body;
    }
    // If body was parsed into an object, we cannot re-stringify reliably;
    // skip scanning rather than producing false positives.
    if (!bodyStr || typeof bodyStr !== 'string') return next();

    const ip = req.wafIp || req.socket?.remoteAddress || 'unknown';

    for (const rule of XXE_RULES) {
      const m = rule.pattern.exec(bodyStr);
      if (m) {
        logBlock({
          logPath:   config.logPath,
          ip,
          method:    req.method,
          path:      req.path,
          rule:      rule.id,
          matched:   m[0].slice(0, 120),
          source:    'body',
          severity:  rule.severity,
          userAgent: req.headers['user-agent'] || '',
        });

        if (config.mode === 'log-only') return next();

        return res.status(403).json({
          blocked: true,
          rule:    rule.id,
          message: 'Request blocked by WAF',
        });
      }
    }

    next();
  };
}

module.exports = createXxeMiddleware;
