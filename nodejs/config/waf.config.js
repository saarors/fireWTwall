'use strict';

module.exports = {
  // Permitted HTTP methods — anything else returns 405
  allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],

  // Maximum Content-Length in bytes (default: 10 MB)
  maxBodySize: 10 * 1024 * 1024,

  // Rate limiting
  rateLimit: {
    windowMs: 60 * 1000,          // 1-minute sliding window
    maxRequests: 100,              // max requests per window
    blockDurationMs: 10 * 60 * 1000, // 10-minute block on violation
  },

  // IPs / CIDR ranges that bypass all checks
  whitelist: [],

  // IPs / CIDR ranges that are always blocked
  blacklist: [],

  // Paths that skip all WAF checks (exact match on req.path)
  bypassPaths: ['/health', '/ping'],

  // Trusted reverse-proxy IPs — enables X-Forwarded-For parsing
  trustedProxies: [],

  // 'reject' → send 403 and stop.  'log-only' → log but let request through.
  mode: 'reject',

  // Absolute or relative path for the log file
  logPath: './logs/waf.log',

  // Block responses: 'json' or 'html'
  responseType: 'json',

  // Debug mode: log every request (pass + block) and add X-WAF-* response headers.
  // Never enable in production — exposes internal rule names in headers.
  debug: false,
};
