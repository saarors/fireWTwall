'use strict';

const { scanSources } = require('../utils/patternMatcher');
const { logBlock }    = require('../utils/logger');

// ── LDAP injection rules ───────────────────────────────────────────────────────
// LDAP filter injection lets attackers bypass authentication or enumerate the
// directory by inserting wildcards, closing/opening filter groups, or null bytes.
const LDAP_RULES = [
  { name: 'ldap-wildcard-bypass', severity: 'high',     pattern: /\*\)\s*\(\s*[a-z]+=\*|^\*$/i,                  description: 'LDAP wildcard filter bypass' },
  { name: 'ldap-injection-paren', severity: 'critical', pattern: /\*\)\s*\(\||\*\)\s*\(&/i,                       description: 'LDAP OR/AND filter injection' },
  { name: 'ldap-injection-null',  severity: 'high',     pattern: /\x00|%00.*uid|uid.*%00/i,                       description: 'LDAP null byte injection' },
  { name: 'ldap-injection-close', severity: 'critical', pattern: /\*\s*\)\s*\(\s*uid\s*=\s*\*/i,                  description: 'LDAP uid wildcard injection' },
  { name: 'ldap-injection-admin', severity: 'critical', pattern: /\*\)\s*\(\s*cn\s*=\s*admin|\)\s*\(\&\s*\(password/i, description: 'LDAP admin/password filter injection' },
  { name: 'ldap-injection-encode',severity: 'high',     pattern: /\*28|\*29|\*00|\*2a/i,                          description: 'LDAP encoded special chars' },
];

/**
 * LDAP injection middleware — scans query params, body, and cookies.
 *
 * @param {object} config - WAF configuration
 * @returns {Function} Express middleware
 */
function createLdapInjectionMiddleware(config) {
  return function ldapInjectionMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    const sources = [
      { label: 'query',   data: req.query },
      { label: 'body',    data: req.body },
      { label: 'cookies', data: req.cookies },
    ];

    const hit = scanSources(sources, LDAP_RULES);

    if (hit) {
      const ip      = req.wafIp || req.socket?.remoteAddress || 'unknown';
      const ruleDef = LDAP_RULES.find((r) => r.name === hit.rule);

      logBlock({
        logPath:   config.logPath,
        ip,
        method:    req.method,
        path:      req.path,
        rule:      hit.rule,
        matched:   hit.matched,
        source:    hit.source,
        severity:  ruleDef?.severity || 'high',
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

module.exports = createLdapInjectionMiddleware;
