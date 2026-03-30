'use strict';

const { deepDecode } = require('../utils/patternMatcher');
const { logBlock }   = require('../utils/logger');

// Parameter names that legitimately reference file paths — RFI is only
// meaningful when the attacker controls which file the server loads.
const FILE_PARAM_NAMES = new Set([
  'page', 'file', 'include', 'require', 'template', 'view', 'document',
  'folder', 'root', 'path', 'pg', 'style', 'pdf', 'layout', 'conf',
  'config', 'inc', 'mod', 'module', 'load', 'show',
]);

// ── Remote File Inclusion rules (applied to param VALUE only) ─────────────────
const RFI_RULES = [
  { name: 'rfi-http',        severity: 'critical', pattern: /^https?:\/\//i,                  description: 'HTTP remote file inclusion' },
  { name: 'rfi-ftp',         severity: 'critical', pattern: /^ftp:\/\//i,                     description: 'FTP remote file inclusion' },
  { name: 'rfi-smb',         severity: 'critical', pattern: /^\\\\[a-z0-9]/i,                 description: 'SMB/UNC remote file inclusion' },
  { name: 'rfi-expect',      severity: 'critical', pattern: /^expect:\/\//i,                  description: 'PHP expect:// wrapper RCE' },
  { name: 'rfi-data',        severity: 'critical', pattern: /^data:text\/plain;base64,/i,     description: 'Data URI RFI' },
  { name: 'rfi-log-poison',  severity: 'critical', pattern: /\/var\/log\/(apache|nginx|httpd|auth|syslog|mail)|\/proc\/self\/environ/i, description: 'LFI log/proc poisoning' },
];

/**
 * Flatten a parsed query / body object to an array of { key, value } pairs.
 * Recurses one level into nested objects (e.g. qs-style ?foo[bar]=baz).
 *
 * @param {object} obj
 * @returns {{ key: string, value: string }[]}
 */
function flattenParams(obj) {
  if (!obj || typeof obj !== 'object') return [];
  const pairs = [];
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === 'string') {
      pairs.push({ key: k, value: v });
    } else if (Array.isArray(v)) {
      for (const item of v) {
        if (typeof item === 'string') pairs.push({ key: k, value: item });
      }
    } else if (v && typeof v === 'object') {
      // One level of nesting (e.g. ?file[path]=...)
      for (const [subK, subV] of Object.entries(v)) {
        if (typeof subV === 'string') pairs.push({ key: subK, value: subV });
      }
    }
  }
  return pairs;
}

/**
 * Test a single decoded value against all RFI rules.
 *
 * @param {string} value
 * @returns {{ rule: string, matched: string } | null}
 */
function matchRfi(value) {
  const decoded = deepDecode(value);
  for (const { name, pattern } of RFI_RULES) {
    const m = pattern.exec(decoded);
    if (m) return { rule: name, matched: m[0].slice(0, 120) };
  }
  return null;
}

/**
 * RFI middleware — only triggers when the parameter NAME suggests a file
 * reference (see FILE_PARAM_NAMES).  Checks both query string and parsed body.
 *
 * @param {object} config - WAF configuration
 * @returns {Function} Express middleware
 */
function createRfiMiddleware(config) {
  return function rfiMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    const paramSources = [
      { label: 'query', data: req.query },
      { label: 'body',  data: req.body  },
    ];

    for (const { label, data } of paramSources) {
      const pairs = flattenParams(data);
      for (const { key, value } of pairs) {
        // Only inspect values whose key name implies a file reference
        if (!FILE_PARAM_NAMES.has(key.toLowerCase())) continue;

        const hit = matchRfi(value);
        if (hit) {
          const ip      = req.wafIp || req.socket?.remoteAddress || 'unknown';
          const ruleDef = RFI_RULES.find((r) => r.name === hit.rule);

          logBlock({
            logPath:   config.logPath,
            ip,
            method:    req.method,
            path:      req.path,
            rule:      hit.rule,
            matched:   hit.matched,
            source:    `${label}:${key}`,
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
      }
    }

    next();
  };
}

module.exports = createRfiMiddleware;
