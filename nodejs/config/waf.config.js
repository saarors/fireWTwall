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

  // Entropy scanner — Shannon entropy analysis of parameter values
  entropy: {
    minLength:           20,  // minimum value length to analyse
    shellcodeThreshold:  6.8, // entropy > this → near-random (shellcode / binary)
    encodedThreshold:    5.5, // entropy > this over len > 50 → multi-encoded payload
    b64Threshold:        5.9, // entropy > this over len > 80 in b64 alphabet → encoded payload
  },

  // Heuristic engine — structural zero-day detection
  heuristic: {
    encodingMixThreshold:    3,  // distinct encoding types in one value → critical
    nestingDepthThreshold:   6,  // bracket nesting depth → high
    keywordDensityThreshold: 3,  // attack keywords per 100 chars → high
    operatorStormThreshold:  15, // attack operators per 100 chars → high
  },

  // Mutation tracker — payload fuzzing / variant detection
  mutation: {
    windowMs:             60_000, // sliding window for unique-variant counting (1 minute)
    maxVariants:          5,      // unique variants within window before alert
    levenshteinThreshold: 10,     // avg edit distance below this = "similar" payloads
    replayThreshold:      10,     // exact fingerprint replays before alert
  },

  // Request rhythm — bot/scanner timing-pattern detection
  rhythm: {
    sampleSize:             10, // requests needed before timing analysis begins
    machineStddevThreshold: 50, // stddev below this (ms) = machine-regular traffic
    burstWindowMs:          200, // all sampleSize requests within this window = burst
    lowSlowJitterMs:        10, // interval jitter tolerance for 1-second cron detection
  },
};
