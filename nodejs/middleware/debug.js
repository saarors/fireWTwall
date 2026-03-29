'use strict';

const crypto = require('crypto');
const { logPass, logBlock } = require('../utils/logger');

/**
 * Debug middleware — bookends the full WAF pipeline.
 *
 * Stamps every request with a requestId + start timer.
 * Wraps res.json() to intercept block responses and add X-WAF-* headers.
 * On res.finish, logs pass events (debug mode) or just sets headers.
 *
 * Safe to leave in the chain when debug: false — all paths are no-ops.
 */
function createDebugMiddleware(config) {
  return function debugMiddleware(req, res, next) {
    req.wafRequestId = crypto.randomBytes(8).toString('hex');
    req.wafStart     = process.hrtime.bigint();

    if (config.debug) {
      res.set('X-WAF-RequestId', req.wafRequestId);
    }

    // Intercept res.json to catch block responses from any downstream middleware
    const originalJson = res.json.bind(res);
    res.json = function debugJson(body) {
      if (config.debug && body && body.blocked === true) {
        const durationMs = elapsedMs(req.wafStart);
        res.set('X-WAF-Result',    'blocked');
        res.set('X-WAF-Rule',      body.rule || 'unknown');
        res.set('X-WAF-Time',      durationMs + 'ms');

        // Also record durationMs in the log — re-log with timing
        logBlock({
          logPath:    config.logPath,
          requestId:  req.wafRequestId,
          ip:         req.wafIp || req.socket?.remoteAddress || 'unknown',
          method:     req.method,
          path:       req.path,
          rule:       body.rule || 'unknown',
          userAgent:  req.headers['user-agent'] || '',
          durationMs: parseFloat(durationMs),
        });
      }
      return originalJson(body);
    };

    res.on('finish', () => {
      // Only runs for requests that passed all checks (res.json with blocked:true
      // was not called, or mode was log-only)
      if (config.debug && !res.getHeader('X-WAF-Result')) {
        const durationMs = elapsedMs(req.wafStart);
        res.setHeader('X-WAF-Result', 'passed');
        res.setHeader('X-WAF-Time',   durationMs + 'ms');

        logPass({
          logPath:    config.logPath,
          requestId:  req.wafRequestId,
          ip:         req.wafIp || req.socket?.remoteAddress || 'unknown',
          method:     req.method,
          path:       req.path,
          userAgent:  req.headers['user-agent'] || '',
          durationMs: parseFloat(durationMs),
        });
      }
    });

    next();
  };
}

function elapsedMs(start) {
  return (Number(process.hrtime.bigint() - start) / 1e6).toFixed(3);
}

module.exports = { createDebugMiddleware };
