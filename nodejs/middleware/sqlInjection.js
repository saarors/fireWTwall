'use strict';

const { scanSources } = require('../utils/patternMatcher');
const { logBlock } = require('../utils/logger');

const SQL_RULES = [
  // Critical — immediate block
  { name: 'sql-union-select',     severity: 'critical', pattern: /\bunion\s+(?:all\s+)?select\b/i },
  { name: 'sql-drop-table',       severity: 'critical', pattern: /;\s*drop\s+table\b/i },
  { name: 'sql-xp-cmdshell',      severity: 'critical', pattern: /\bxp_cmdshell\b/i },
  { name: 'sql-exec',             severity: 'critical', pattern: /\bexec(?:ute)?\s*\(/i },
  { name: 'sql-information-schema', severity: 'critical', pattern: /\binformation_schema\b/i },
  { name: 'sql-sleep',            severity: 'critical', pattern: /\bsleep\s*\(\s*\d/i },
  { name: 'sql-benchmark',        severity: 'critical', pattern: /\bbenchmark\s*\(/i },
  { name: 'sql-load-file',        severity: 'critical', pattern: /\bload_file\s*\(/i },
  { name: 'sql-into-outfile',     severity: 'critical', pattern: /\binto\s+(?:out|dump)file\b/i },
  { name: 'sql-sys-tables',       severity: 'critical', pattern: /\bsysobjects\b|\bsyscolumns\b/i },

  // High
  { name: 'sql-comment',          severity: 'high',     pattern: /(?:--|\/\*|\*\/|#\s*$)/m },
  { name: 'sql-stacked-query',    severity: 'high',     pattern: /;\s*(?:select|insert|update|delete|drop|alter|create|exec)\b/i },
  { name: 'sql-cast-convert',     severity: 'high',     pattern: /\b(?:cast|convert)\s*\(/i },
  { name: 'sql-char-concat',      severity: 'high',     pattern: /\bchar\s*\(\s*\d/i },

  // Medium
  { name: 'sql-boolean-true',     severity: 'medium',   pattern: /\bor\s+['"0-9]+\s*=\s*['"0-9]+/i },
  { name: 'sql-boolean-and',      severity: 'medium',   pattern: /\band\s+['"0-9]+\s*=\s*['"0-9]+/i },
  { name: 'sql-order-by-num',     severity: 'medium',   pattern: /\border\s+by\s+\d+\b/i },
  { name: 'sql-tautology',        severity: 'medium',   pattern: /'\s*or\s*'[^']*'\s*=\s*'/i },
  // Additional coverage
  { name: 'sql-waitfor-delay',    severity: 'critical', pattern: /\bwaitfor\s+delay\b/i },
  { name: 'sql-pg-sleep',         severity: 'critical', pattern: /\bpg_sleep\s*\(/i },
  { name: 'sql-hex-values',       severity: 'medium',   pattern: /0x[0-9a-f]{4,}/i },
  { name: 'sql-group-by-having',  severity: 'medium',   pattern: /\bhaving\s+\d+\s*=\s*\d+/i },
  { name: 'sql-dbms-fingerprint', severity: 'medium',   pattern: /\b(?:@@version|version\s*\(\s*\)|user\s*\(\s*\)|database\s*\(\s*\))\b/i },
  { name: 'sql-declare-set',      severity: 'high',     pattern: /\bdeclare\s+@\w+\b/i },
  { name: 'sql-bulk-insert',      severity: 'critical', pattern: /\bbulk\s+insert\b/i },
  { name: 'sql-openrowset',       severity: 'critical', pattern: /\bopenrowset\s*\(/i },
];

function createSqlInjectionMiddleware(config) {
  return function sqlInjectionMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    const sources = [
      { label: 'query', data: req.query },
      { label: 'body',  data: req.body },
      { label: 'path',  data: req.path },
      { label: 'cookies', data: req.cookies },
    ];

    const hit = scanSources(sources, SQL_RULES);

    if (hit) {
      const ip = req.wafIp || req.socket?.remoteAddress || 'unknown';
      const ruleDef = SQL_RULES.find((r) => r.name === hit.rule);

      logBlock({
        logPath: config.logPath,
        ip,
        method: req.method,
        path: req.path,
        rule: hit.rule,
        matched: hit.matched,
        source: hit.source,
        severity: ruleDef?.severity || 'medium',
        userAgent: req.headers['user-agent'] || '',
      });

      if (config.mode === 'log-only') return next();

      return res.status(403).json({
        blocked: true,
        rule: hit.rule,
        message: 'Request blocked by WAF',
      });
    }

    next();
  };
}

module.exports = createSqlInjectionMiddleware;
