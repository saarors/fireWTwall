'use strict';

const { deepDecode, scanSources } = require('../utils/patternMatcher');
const { logBlock }                = require('../utils/logger');

// ── Shellshock rules (CVE-2014-6271 / CVE-2014-7169) ─────────────────────────
// Attackers inject the bash function-definition syntax into any HTTP header
// that a CGI application (or similar) might pass to a shell as an environment
// variable.  The most common vectors are User-Agent, Referer, Cookie, and
// arbitrary custom headers, but every header value must be checked.
const SHELLSHOCK_RULES = [
  { name: 'shellshock-func',    severity: 'critical', pattern: /\(\s*\)\s*\{\s*[^}]*\}\s*;/,  description: 'Shellshock bash function definition' },
  { name: 'shellshock-env-cmd', severity: 'critical', pattern: /\(\s*\)\s*\{\s*:;\s*\}\s*;/,  description: 'Shellshock () { :; }; payload' },
];

/**
 * Shellshock middleware — scans ALL request headers, query params, and body.
 *
 * CGI environments export every HTTP header as an environment variable, so the
 * full header map (not just User-Agent / Referer) must be checked.
 *
 * @param {object} config - WAF configuration
 * @returns {Function} Express middleware
 */
function createShellshockMiddleware(config) {
  return function shellshockMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    // 1. Scan all request headers
    for (const [headerName, headerValue] of Object.entries(req.headers)) {
      const value   = Array.isArray(headerValue) ? headerValue.join(', ') : String(headerValue);
      const decoded = deepDecode(value);

      for (const { name, pattern, severity } of SHELLSHOCK_RULES) {
        const m = pattern.exec(decoded);
        if (m) {
          const ip = req.wafIp || req.socket?.remoteAddress || 'unknown';

          logBlock({
            logPath:   config.logPath,
            ip,
            method:    req.method,
            path:      req.path,
            rule:      name,
            matched:   m[0].slice(0, 120),
            source:    `header:${headerName}`,
            severity,
            userAgent: req.headers['user-agent'] || '',
          });

          if (config.mode === 'log-only') return next();

          return res.status(403).json({
            blocked: true,
            rule:    name,
            message: 'Request blocked by WAF',
          });
        }
      }
    }

    // 2. Scan query params and body
    const sources = [
      { label: 'query', data: req.query },
      { label: 'body',  data: req.body },
    ];

    const hit = scanSources(sources, SHELLSHOCK_RULES);

    if (hit) {
      const ip      = req.wafIp || req.socket?.remoteAddress || 'unknown';
      const ruleDef = SHELLSHOCK_RULES.find((r) => r.name === hit.rule);

      logBlock({
        logPath:   config.logPath,
        ip,
        method:    req.method,
        path:      req.path,
        rule:      hit.rule,
        matched:   hit.matched,
        source:    hit.source,
        severity:  ruleDef?.severity || 'critical',
        userAgent: req.headers['user-agent'] || '',
      });

      if (config.mode === 'log-only') return next();

      return res.status(403).json({
        blocked: true,
        rule:    hit.rule,
        message: 'Request blocked by WAF',
      });
    }

    next();
  };
}

module.exports = createShellshockMiddleware;
