'use strict';

const { logBlock } = require('../utils/logger');

// ─── Standard Deviation ─────────────────────────────────────────────────────

/**
 * Compute population standard deviation for an array of numbers.
 * Returns 0 for single-element arrays.
 *
 * @param {number[]} arr
 * @returns {number}
 */
function stddev(arr) {
  if (arr.length < 2) return 0;
  const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
  return Math.sqrt(
    arr.reduce((sum, x) => sum + (x - mean) ** 2, 0) / arr.length
  );
}

// ─── In-Memory Store ────────────────────────────────────────────────────────

// Map<ip, { timestamps: number[], blocked: boolean, blockedUntil: number }>
const store = new Map();

// Prune IPs not seen in the last 10 minutes every 10 minutes
const PRUNE_INTERVAL_MS  = 10 * 60 * 1000;
const PRUNE_IDLE_CUTOFF  = 10 * 60 * 1000;

const pruneTimer = setInterval(() => {
  const cutoff = Date.now() - PRUNE_IDLE_CUTOFF;
  for (const [ip, state] of store) {
    const lastSeen = state.timestamps[state.timestamps.length - 1] || 0;
    if (lastSeen < cutoff) store.delete(ip);
  }
}, PRUNE_INTERVAL_MS);

// Allow the process to exit cleanly even while this timer is pending
if (pruneTimer.unref) pruneTimer.unref();

// ─── Block Helper ───────────────────────────────────────────────────────────

/**
 * Log and optionally block a request that triggered a rhythm rule.
 *
 * @param {object}   opts
 * @param {object}   opts.req
 * @param {object}   opts.config
 * @param {string}   opts.ip
 * @param {object}   opts.state
 * @param {string}   opts.ruleId
 * @param {string}   opts.severity
 * @param {string}   opts.detail
 * @param {number}   opts.blockMs   - how long to block in milliseconds
 * @param {Function} opts.next
 * @param {object}   opts.res
 * @returns {void}
 */
function handleRhythmHit({ req, config, ip, state, ruleId, severity, detail, blockMs, next, res }) {
  state.blocked      = true;
  state.blockedUntil = Date.now() + blockMs;

  logBlock({
    logPath:   config.logPath,
    requestId: req.wafRequestId,
    ip,
    method:    req.method,
    path:      req.path,
    rule:      ruleId,
    matched:   detail,
    source:    'request-rhythm',
    severity,
    userAgent: req.headers['user-agent'] || '',
  });

  if (config.mode === 'log-only') return next();

  return res.status(403).json({
    blocked: true,
    rule:    ruleId,
    message: 'Request blocked by WAF',
  });
}

// ─── Middleware Factory ─────────────────────────────────────────────────────

/**
 * Create the request rhythm middleware.
 *
 * Detects automated / bot traffic by analysing the TIMING PATTERN of requests
 * from the same IP.  Human users are irregular; scanners and bots are
 * mechanically regular.
 *
 * Three detection modes:
 *   1. Machine-regular  — very low stddev, high request rate
 *   2. Burst scanner    — 10 requests within 200 ms total
 *   3. Low-and-slow     — requests arriving at exactly 1-second intervals
 *                         (cron-job or scheduled scanner)
 *
 * @param {object} config - WAF configuration (uses config.rhythm section)
 * @returns {Function} Express middleware
 */
module.exports = function createRequestRhythmMiddleware(config) {
  const cfg                   = config.rhythm || {};
  const sampleSize            = cfg.sampleSize            || 10;
  const machineStddevThreshold = cfg.machineStddevThreshold || 50;   // ms
  const burstWindowMs         = cfg.burstWindowMs         || 200;    // ms
  const lowSlowJitterMs       = cfg.lowSlowJitterMs       || 10;     // ms
  const MAX_TIMESTAMPS        = 25; // keep more than sampleSize for low-and-slow

  return function requestRhythmMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    const ip  = req.wafIp || req.ip || req.socket?.remoteAddress || 'unknown';
    const now = Date.now();

    // Retrieve or create state
    if (!store.has(ip)) {
      store.set(ip, { timestamps: [], blocked: false, blockedUntil: 0 });
    }
    const state = store.get(ip);

    // ── Check active block ─────────────────────────────────────────────
    if (state.blocked) {
      if (now < state.blockedUntil) {
        logBlock({
          logPath:   config.logPath,
          requestId: req.wafRequestId,
          ip,
          method:    req.method,
          path:      req.path,
          rule:      'rhythm-active-block',
          matched:   `blocked until ${new Date(state.blockedUntil).toISOString()}`,
          source:    'request-rhythm',
          severity:  'high',
          userAgent: req.headers['user-agent'] || '',
        });

        if (config.mode === 'log-only') return next();
        return res.status(403).json({ blocked: true, rule: 'rhythm-active-block', message: 'Request blocked by WAF' });
      } else {
        // Block expired — reset
        state.blocked      = false;
        state.blockedUntil = 0;
        state.timestamps   = [];
      }
    }

    // ── Record timestamp ───────────────────────────────────────────────
    state.timestamps.push(now);
    if (state.timestamps.length > MAX_TIMESTAMPS) state.timestamps.shift();

    // Need at least sampleSize timestamps before analysis
    if (state.timestamps.length < sampleSize) return next();

    // Compute inter-request intervals (ms between consecutive requests)
    const ts        = state.timestamps;
    const intervals = [];
    for (let i = 1; i < ts.length; i++) {
      intervals.push(ts[i] - ts[i - 1]);
    }

    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const sd   = stddev(intervals);

    // ── Rule: Machine-Regular ────────────────────────────────────────
    // Very low timing variance + high rate = bot
    if (sd < machineStddevThreshold && mean < 500 && intervals.length >= sampleSize) {
      return handleRhythmHit({
        req, config, ip, state, res, next,
        ruleId:   'rhythm-machine-regular',
        severity: 'critical',
        detail:   `stddev=${sd.toFixed(1)}ms mean=${mean.toFixed(1)}ms samples=${intervals.length}`,
        blockMs:  5 * 60 * 1000, // 5 minutes
      });
    }

    // ── Rule: Burst Scanner ──────────────────────────────────────────
    // All sampleSize requests arrived within burstWindowMs total
    const windowSlice = ts.slice(-sampleSize);
    const totalSpan   = windowSlice[windowSlice.length - 1] - windowSlice[0];

    if (windowSlice.length >= sampleSize && totalSpan <= burstWindowMs) {
      return handleRhythmHit({
        req, config, ip, state, res, next,
        ruleId:   'rhythm-scanner-burst',
        severity: 'high',
        detail:   `${sampleSize} requests in ${totalSpan}ms (threshold: ${burstWindowMs}ms)`,
        blockMs:  2 * 60 * 1000, // 2 minutes
      });
    }

    // ── Rule: Low-and-Slow (cron scanner) ───────────────────────────
    // 20+ requests from same IP with all intervals within 1000ms ± lowSlowJitterMs
    if (state.timestamps.length >= 20) {
      // Use all available intervals for this rule
      const lowSlowIntervals = [];
      for (let i = 1; i < ts.length; i++) {
        lowSlowIntervals.push(ts[i] - ts[i - 1]);
      }
      const target      = 1000; // 1 second target interval
      const allCronLike = lowSlowIntervals.every(
        (iv) => Math.abs(iv - target) <= lowSlowJitterMs
      );

      if (allCronLike) {
        return handleRhythmHit({
          req, config, ip, state, res, next,
          ruleId:   'rhythm-low-and-slow',
          severity: 'high',
          detail:   `${lowSlowIntervals.length} intervals all within 1000ms ±${lowSlowJitterMs}ms`,
          blockMs:  30 * 60 * 1000, // 30 minutes
        });
      }
    }

    next();
  };
};
