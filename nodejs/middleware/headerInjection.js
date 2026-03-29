'use strict';

const { deepDecode } = require('../utils/patternMatcher');
const { logBlock } = require('../utils/logger');

// CRLF characters used for HTTP response splitting
const CRLF_PATTERN = /[\r\n]|%0[aAdD]|\\r|\\n/i;

// Headers that, if user-controlled, could cause response splitting or cache poisoning
const SENSITIVE_HEADERS = [
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-original-url',
  'x-rewrite-url',
  'x-http-method-override',
  'x-http-method',
  'x-method-override',
];

function createHeaderInjectionMiddleware(config) {
  return function headerInjectionMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    const ip = req.wafIp || req.socket?.remoteAddress || 'unknown';

    // 1. CRLF injection — scan all header values
    for (const [name, value] of Object.entries(req.headers)) {
      const decoded = deepDecode(String(value));
      if (CRLF_PATTERN.test(decoded)) {
        logBlock({
          logPath: config.logPath,
          ip,
          method: req.method,
          path: req.path,
          rule: 'crlf-injection',
          matched: decoded.slice(0, 120),
          source: `header:${name}`,
          severity: 'critical',
          userAgent: req.headers['user-agent'] || '',
        });

        if (config.mode === 'log-only') break;

        return res.status(400).json({
          blocked: true,
          rule: 'crlf-injection',
          message: 'Request blocked by WAF',
        });
      }
    }

    // 2. Host header injection — value should not contain path characters
    const host = req.headers['host'] || '';
    if (host && /[/?#@\r\n]/.test(host)) {
      logBlock({
        logPath: config.logPath,
        ip,
        method: req.method,
        path: req.path,
        rule: 'host-header-injection',
        matched: host.slice(0, 120),
        source: 'header:host',
        severity: 'high',
        userAgent: req.headers['user-agent'] || '',
      });

      if (config.mode !== 'log-only') {
        return res.status(400).json({
          blocked: true,
          rule: 'host-header-injection',
          message: 'Request blocked by WAF',
        });
      }
    }

    next();
  };
}

module.exports = createHeaderInjectionMiddleware;
