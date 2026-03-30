'use strict';

module.exports = {
  // Permitted HTTP methods — anything else returns 405
  allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],

  // Maximum Content-Length in bytes (default: 10 MB)
  maxBodySize: 10 * 1024 * 1024,

  // DDoS protection
  ddos: {
    maxUrlLength:   2048,          // block requests with URL longer than this
    maxHeaderCount: 100,           // block requests with more than this many headers
    maxHeaderSize:  8192,          // block if any header value exceeds this (bytes)
    burst: {
      windowMs:        1_000,      // 1-second burst window
      maxRequests:     20,         // max requests per IP per second
      blockDurationMs: 60_000,     // 1-minute block after burst violation
    },
    global: {
      windowMs:    1_000,          // global window
      maxRequests: 500,            // total requests/second across all IPs
    },
    fingerprint: {
      windowMs:        10_000,     // 10-second fingerprint window
      maxRequests:     50,         // max same (IP+UA+path) hits
      blockDurationMs: 60_000,
    },
    pathFlood: {
      windowMs:    5_000,          // 5-second path flood window
      maxRequests: 200,            // max hits on same path across all IPs
    },
    tarpit: {
      enabled: false,              // delay repeat offenders instead of instant block
      delayMs: 2_000,              // delay in ms
    },
  },

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
