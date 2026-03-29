'use strict';

const path = require('path');
const { logBlock } = require('../utils/logger');

// Load bot config once at module load — require() is cached after first call
const botsConfig = require(path.resolve(__dirname, '../config/bad-bots.json'));

const blockedPatterns = botsConfig.blocked.map(
  (s) => new RegExp(s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i')
);
const allowedPatterns = botsConfig.allowed.map(
  (s) => new RegExp(s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i')
);
const blockEmptyUA = botsConfig.blockEmptyUserAgent !== false; // default true

function createBotFilterMiddleware(config) {
  return function botFilterMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    const ua = req.headers['user-agent'] || '';
    const ip = req.wafIp || req.socket?.remoteAddress || 'unknown';

    // Block missing / empty User-Agent — no legitimate browser or API client omits it
    if (ua === '' && blockEmptyUA) {
      logBlock({
        logPath: config.logPath,
        ip,
        method: req.method,
        path: req.path,
        rule: 'missing-user-agent',
        matched: '',
        source: 'user-agent',
        severity: 'medium',
        userAgent: '',
      });

      if (config.mode !== 'log-only') {
        return res.status(403).json({
          blocked: true,
          rule: 'missing-user-agent',
          message: 'Access denied',
        });
      }
    }

    // Allowed bots always pass
    if (allowedPatterns.some((p) => p.test(ua))) return next();

    const hit = blockedPatterns.find((p) => p.test(ua));
    if (hit) {
      logBlock({
        logPath: config.logPath,
        ip,
        method: req.method,
        path: req.path,
        rule: 'bad-bot',
        matched: ua.slice(0, 120),
        source: 'user-agent',
        severity: 'high',
        userAgent: ua,
      });

      if (config.mode === 'log-only') return next();

      return res.status(403).json({
        blocked: true,
        rule: 'bad-bot',
        message: 'Access denied',
      });
    }

    next();
  };
}

module.exports = createBotFilterMiddleware;
