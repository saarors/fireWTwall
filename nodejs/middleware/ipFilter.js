'use strict';

const { ipInList, extractIp } = require('../utils/ipUtils');
const { logBlock } = require('../utils/logger');

function createIpFilterMiddleware(config) {
  return function ipFilterMiddleware(req, res, next) {
    const ip = extractIp(req, config.trustedProxies);
    req.wafIp = ip; // Cache for downstream middleware

    // Whitelist: bypass all subsequent checks
    if (config.whitelist.length > 0 && ipInList(ip, config.whitelist)) {
      req.wafTrusted = true;
      return next();
    }

    // Blacklist: always block
    if (config.blacklist.length > 0 && ipInList(ip, config.blacklist)) {
      logBlock({
        logPath: config.logPath,
        ip,
        method: req.method,
        path: req.path,
        rule: 'ip-blacklist',
        severity: 'high',
        userAgent: req.headers['user-agent'] || '',
      });

      if (config.mode === 'log-only') return next();

      return res.status(403).json({
        blocked: true,
        rule: 'ip-blacklist',
        message: 'Access denied',
      });
    }

    next();
  };
}

module.exports = createIpFilterMiddleware;
