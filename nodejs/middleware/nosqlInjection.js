'use strict';

const { scanSources, deepDecode } = require('../utils/patternMatcher');
const { logBlock }                = require('../utils/logger');

// ── NoSQL / MongoDB injection rules ───────────────────────────────────────────
// Two attack surfaces:
//   1. JSON body — attacker sends {"username": {"$ne": null}} to bypass auth.
//   2. Query string bracket notation — ?user[$ne]=1 which Express/qs parses
//      into { user: { '$ne': '1' } }.  The raw query string is also checked
//      for bracket-notation patterns that survive before qs parsing.
const NOSQL_RULES = [
  // ── Operator injection ────────────────────────────────────────────────────
  { name: 'nosql-operator-ne',    severity: 'high',     pattern: /\[\s*\$ne\s*\]|"\s*\$ne\s*"\s*:/i,    description: 'MongoDB $ne operator injection' },
  { name: 'nosql-operator-gt',    severity: 'high',     pattern: /\[\s*\$gt\s*\]|"\s*\$gt\s*"\s*:/i,    description: 'MongoDB $gt operator injection' },
  { name: 'nosql-operator-lt',    severity: 'high',     pattern: /\[\s*\$lt\s*\]|"\s*\$lt\s*"\s*:/i,    description: 'MongoDB $lt operator injection' },
  { name: 'nosql-operator-gte',   severity: 'high',     pattern: /\[\s*\$gte\s*\]|"\s*\$gte\s*"\s*:/i,  description: 'MongoDB $gte operator injection' },
  { name: 'nosql-operator-lte',   severity: 'high',     pattern: /\[\s*\$lte\s*\]|"\s*\$lte\s*"\s*:/i,  description: 'MongoDB $lte operator injection' },
  { name: 'nosql-operator-where', severity: 'critical', pattern: /"\s*\$where\s*"\s*:/i,                 description: 'MongoDB $where JS injection' },
  { name: 'nosql-operator-regex', severity: 'high',     pattern: /\[\s*\$regex\s*\]|"\s*\$regex\s*"\s*:/i, description: 'MongoDB $regex injection' },
  { name: 'nosql-operator-in',    severity: 'medium',   pattern: /"\s*\$in\s*"\s*:\s*\[/i,               description: 'MongoDB $in operator injection' },
  { name: 'nosql-operator-or',    severity: 'medium',   pattern: /"\s*\$or\s*"\s*:\s*\[/i,               description: 'MongoDB $or injection' },
  { name: 'nosql-operator-expr',  severity: 'high',     pattern: /"\s*\$expr\s*"\s*:/i,                  description: 'MongoDB $expr aggregation injection' },

  // ── Blind injection via $where + sleep ────────────────────────────────────
  { name: 'nosql-func-sleep',     severity: 'critical', pattern: /"\s*\$where\s*"\s*:\s*["']?.*sleep\s*\(/i, description: 'MongoDB $where sleep blind injection' },
];

/**
 * Scan the raw query string for bracket-notation MongoDB operators such as
 * ?user[$ne]=1 before they are parsed by qs/Express into an object.
 *
 * @param {string} rawQuery - req.url query string portion (after '?')
 * @returns {{ rule: string, matched: string } | null}
 */
function scanRawQuery(rawQuery) {
  if (!rawQuery) return null;
  const decoded = deepDecode(rawQuery);

  // Bracket-notation pattern: [<$operator>]
  const bracketOp = /\[\s*\$[a-zA-Z]+\s*\]/;
  const m = bracketOp.exec(decoded);
  if (m) {
    // Identify which operator to return an accurate rule name
    const op = m[0].replace(/[\[\]\s]/g, '').toLowerCase();
    const rule = NOSQL_RULES.find((r) => r.name === `nosql-operator-${op.slice(1)}`);
    return {
      rule:    rule ? rule.name : 'nosql-operator-ne',
      matched: m[0].slice(0, 120),
    };
  }
  return null;
}

/**
 * NoSQL injection middleware — scans query params, JSON body, and raw query
 * string for MongoDB operator injection patterns.
 *
 * @param {object} config - WAF configuration
 * @returns {Function} Express middleware
 */
function createNosqlInjectionMiddleware(config) {
  return function nosqlInjectionMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    // 1. Check raw query string for bracket-notation operators (?x[$ne]=1)
    const rawQuery  = req.url ? req.url.split('?')[1] : '';
    const rawHit    = scanRawQuery(rawQuery);

    if (rawHit) {
      const ip      = req.wafIp || req.socket?.remoteAddress || 'unknown';
      const ruleDef = NOSQL_RULES.find((r) => r.name === rawHit.rule);

      logBlock({
        logPath:   config.logPath,
        ip,
        method:    req.method,
        path:      req.path,
        rule:      rawHit.rule,
        matched:   rawHit.matched,
        source:    'query-raw',
        severity:  ruleDef?.severity || 'high',
        userAgent: req.headers['user-agent'] || '',
      });

      if (config.mode === 'log-only') return next();

      return res.status(403).json({
        blocked: true,
        rule:    rawHit.rule,
        message: 'Request blocked by WAF',
      });
    }

    // 2. Scan parsed query params and parsed JSON body
    const sources = [
      { label: 'query', data: req.query },
      { label: 'body',  data: req.body },
    ];

    const hit = scanSources(sources, NOSQL_RULES);

    if (hit) {
      const ip      = req.wafIp || req.socket?.remoteAddress || 'unknown';
      const ruleDef = NOSQL_RULES.find((r) => r.name === hit.rule);

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

module.exports = createNosqlInjectionMiddleware;
