'use strict';

const { deepDecode, scanSources } = require('../utils/patternMatcher');
const { logBlock }                = require('../utils/logger');

// ── Log4Shell / JNDI injection rules (CVE-2021-44228 and variants) ────────────
// Attackers embed JNDI lookup strings in any header value, query param, body
// field, or cookie — even using ${lower:j}ndi-style obfuscation — hoping the
// Java application logs the value through log4j.
const LOG4SHELL_RULES = [
  { name: 'log4shell-jndi',              severity: 'critical', pattern: /\$\{jndi\s*:/i,                       description: 'Log4Shell JNDI lookup' },
  { name: 'log4shell-jndi-ldap',         severity: 'critical', pattern: /\$\{jndi\s*:\s*(ldap|ldaps|rmi|dns|iiop|corba|nds|http)s?:\/\//i, description: 'Log4Shell JNDI protocol' },
  { name: 'log4shell-obfuscated-lower',  severity: 'critical', pattern: /\$\{.*lower.*j.*ndi|j\$\{.*\}ndi/i,  description: 'Log4Shell obfuscated with ${lower:}' },
  { name: 'log4shell-obfuscated-upper',  severity: 'critical', pattern: /\$\{.*upper.*j.*ndi/i,                description: 'Log4Shell obfuscated with ${upper:}' },
  { name: 'log4shell-double-colon',      severity: 'critical', pattern: /\$\{\s*::-[jJ]\s*\}/i,               description: 'Log4Shell ${::-j} colon escape' },
  { name: 'log4shell-nested',            severity: 'critical', pattern: /\$\{[^}]*\$\{[^}]*\}[^}]*jndi/i,    description: 'Log4Shell nested expression' },
];

/**
 * Log4Shell middleware — scans ALL request headers (not just well-known ones),
 * query params, body fields, and cookies.
 *
 * Attackers routinely inject JNDI strings into User-Agent, X-Forwarded-For,
 * X-Api-Version, and other arbitrary headers, so the full header map must be
 * checked.
 *
 * @param {object} config - WAF configuration
 * @returns {Function} Express middleware
 */
function createLog4shellMiddleware(config) {
  return function log4shellMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    // 1. Scan all header values (the primary vector for Log4Shell)
    for (const [headerName, headerValue] of Object.entries(req.headers)) {
      const value = Array.isArray(headerValue) ? headerValue.join(', ') : String(headerValue);
      const decoded = deepDecode(value);

      for (const { name, pattern, severity } of LOG4SHELL_RULES) {
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

    // 2. Scan query params, body, and cookies
    const sources = [
      { label: 'query',   data: req.query },
      { label: 'body',    data: req.body },
      { label: 'cookies', data: req.cookies },
    ];

    const hit = scanSources(sources, LOG4SHELL_RULES);

    if (hit) {
      const ip      = req.wafIp || req.socket?.remoteAddress || 'unknown';
      const ruleDef = LOG4SHELL_RULES.find((r) => r.name === hit.rule);

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

module.exports = createLog4shellMiddleware;
