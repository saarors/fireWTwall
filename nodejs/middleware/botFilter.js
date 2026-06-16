'use strict';

const path = require('path');
const { logBlock } = require('../utils/logger');

const botsConfig = require(path.resolve(__dirname, '../config/bad-bots.json'));

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Compile patterns once
const blockedPatterns = (botsConfig.blocked || []).map(
  (s) => new RegExp(escapeRegex(s), 'i')
);

const allowedPatterns = (botsConfig.allowed || []).map(
  (s) => new RegExp(escapeRegex(s), 'i')
);

const blockEmptyUA = botsConfig.blockEmptyUserAgent !== false;

const suspiciousPatterns = [
  /^(curl|wget|python|perl|ruby|php|java|go|node)[\s\/\-]/i,
  /^libcurl/i,
  /^httpclient/i,
  /^apache-httpclient/i,
  /^okhttpclient/i,
  /^java\.net\.urlconnection/i,
  /^scrapy/i,
  /^mechanize/i,
  /^urllib/i,
];

function isSuspiciousUA(ua = '') {
  return suspiciousPatterns.some((p) => p.test(ua));
}

function sendBlocked(res, status, payload, mode) {
  if (mode === 'log-only') return false;
  res.status(status).json(payload);
  return true;
}

function createBotFilterMiddleware(config) {
  return function botFilterMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    const ua = req.headers['user-agent'] || '';
    const ip = req.wafIp || req.socket?.remoteAddress || 'unknown';

    const acceptLang = req.headers['accept-language'] || '';
    const secChUa = req.headers['sec-ch-ua'] || '';

    const logBase = {
      logPath: config.logPath,
      ip,
      method: req.method,
      path: req.path,
    };

    // Weak signal: missing UA (don’t hard block in modern environments)
    if (!ua && blockEmptyUA) {
      logBlock({
        ...logBase,
        rule: 'missing-user-agent',
        matched: '',
        source: 'user-agent',
        severity: 'low',
        userAgent: '',
      });

      if (sendBlocked(res, 403, {
        blocked: true,
        rule: 'missing-user-agent',
        message: 'Access denied',
      }, config.mode)) return;

      return next();
    }

    // Allowed bots
    if (allowedPatterns.some((p) => p.test(ua))) return next();

    // Blocklist
    const blocked = blockedPatterns.find((p) => p.test(ua));
    if (blocked) {
      logBlock({
        ...logBase,
        rule: 'bad-bot',
        matched: ua.slice(0, 120),
        source: 'user-agent',
        severity: 'high',
        userAgent: ua,
      });

      if (sendBlocked(res, 403, {
        blocked: true,
        rule: 'bad-bot',
        message: 'Access denied',
      }, config.mode)) return;

      return next();
    }

    // Suspicious automation
    if (isSuspiciousUA(ua)) {
      logBlock({
        ...logBase,
        rule: 'suspicious-automation',
        matched: ua.slice(0, 120),
        source: 'user-agent',
        severity: 'high',
        userAgent: ua,
      });

      if (sendBlocked(res, 403, {
        blocked: true,
        rule: 'suspicious-automation',
        message: 'Access denied',
      }, config.mode)) return;

      return next();
    }

    // Optional weak bot signals (not blocking alone)
    if (!acceptLang && !secChUa && ua.length < 10) {
      logBlock({
        ...logBase,
        rule: 'low-signal-request',
        matched: ua,
        source: 'headers',
        severity: 'low',
        userAgent: ua,
      });
    }

    next();
  };
}

module.exports = createBotFilterMiddleware;
