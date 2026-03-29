'use strict';

const { scanSources } = require('../utils/patternMatcher');
const { logBlock } = require('../utils/logger');

const PATH_RULES = [
  // Traversal sequences
  { name: 'path-traversal-dotdot', severity: 'critical', pattern: /(?:\.\.[\\/]|[\\/]\.\.)/  },
  { name: 'path-traversal-encoded', severity: 'critical', pattern: /%2e%2e[%2f5c]/i },
  { name: 'path-traversal-unicode', severity: 'critical', pattern: /(?:%c0%ae|%c1%9c)/i },
  { name: 'path-null-byte',         severity: 'critical', pattern: /%00|\x00/ },

  // Sensitive file access
  { name: 'path-etc-passwd',   severity: 'critical', pattern: /\/etc\/(?:passwd|shadow|hosts|group)\b/ },
  { name: 'path-win-system',   severity: 'critical', pattern: /(?:c:|%systemroot%)[/\\]/i },
  { name: 'path-env-file',     severity: 'high',     pattern: /(?:^|\/)\.env(?:\.|$)/ },
  { name: 'path-wp-config',    severity: 'high',     pattern: /wp-config\.php/i },
  { name: 'path-htaccess',     severity: 'high',     pattern: /\.htaccess\b/i },
  { name: 'path-git-config',   severity: 'high',     pattern: /\.git[\\/]/i },
  { name: 'path-ssh-keys',     severity: 'high',     pattern: /\.ssh[\\/]/i },
  { name: 'path-proc-self',    severity: 'critical', pattern: /\/proc\/self\//i },
  { name: 'path-php-wrappers', severity: 'high',     pattern: /(?:php|zip|phar|data|expect|glob|file):\/\//i },
  { name: 'path-php-filter',   severity: 'high',     pattern: /php:\/\/(?:filter|input|stdin)/i },
];

function createPathTraversalMiddleware(config) {
  return function pathTraversalMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    const sources = [
      { label: 'path',  data: req.originalUrl || req.url },
      { label: 'query', data: req.query },
      { label: 'body',  data: req.body },
    ];

    const hit = scanSources(sources, PATH_RULES);

    if (hit) {
      const ip = req.wafIp || req.socket?.remoteAddress || 'unknown';
      const ruleDef = PATH_RULES.find((r) => r.name === hit.rule);

      logBlock({
        logPath: config.logPath,
        ip,
        method: req.method,
        path: req.path,
        rule: hit.rule,
        matched: hit.matched,
        source: hit.source,
        severity: ruleDef?.severity || 'high',
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

module.exports = createPathTraversalMiddleware;
