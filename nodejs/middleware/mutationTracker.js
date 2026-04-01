'use strict';

const { logBlock } = require('../utils/logger');
const { flattenValues } = require('../utils/patternMatcher');

// ─── Levenshtein Distance ───────────────────────────────────────────────────

/**
 * Compute the Levenshtein edit distance between two strings.
 * Simple iterative DP — no external dependencies.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;

  // Build a (m+1) × (n+1) matrix initialised to 0
  const dp = Array.from({ length: m + 1 }, (_, i) => {
    const row = new Array(n + 1).fill(0);
    row[0] = i; // deletions from a
    return row;
  });
  for (let j = 0; j <= n; j++) dp[0][j] = j; // insertions into a

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1]; // characters match — no cost
      } else {
        dp[i][j] =
          1 +
          Math.min(
            dp[i - 1][j],     // deletion
            dp[i][j - 1],     // insertion
            dp[i - 1][j - 1], // substitution
          );
      }
    }
  }

  return dp[m][n];
}

// ─── Fingerprint Helpers ────────────────────────────────────────────────────

// Characters that suggest a value is a potential attack payload
const SUSPICIOUS_CHARS = /[<>'"%;|&]/;

/**
 * Return the first "suspicious" string value found across query + body.
 * Returns null if no suspicious value is present.
 *
 * @param {object} req
 * @returns {string | null}
 */
function extractSuspiciousValue(req) {
  const candidates = [];

  if (req.query && typeof req.query === 'object') {
    candidates.push(...flattenValues(req.query));
  }
  if (req.body) {
    if (typeof req.body === 'string') {
      candidates.push(req.body);
    } else if (typeof req.body === 'object') {
      candidates.push(...flattenValues(req.body));
    }
  }

  for (const v of candidates) {
    if (typeof v === 'string' && SUSPICIOUS_CHARS.test(v)) return v;
  }
  return null;
}

/**
 * Normalise a raw payload value into a stable fingerprint:
 *   - lowercase
 *   - collapse all whitespace
 *   - strip all digits
 *
 * This makes minor mutations (e.g. changing a numeric literal) invisible so
 * we can detect the underlying structural pattern being fuzzed.
 *
 * @param {string} value
 * @returns {string}
 */
function fingerprint(value) {
  return value
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .replace(/\d+/g, '');
}

// ─── Average Levenshtein ────────────────────────────────────────────────────

/**
 * Compute the average pairwise Levenshtein distance for the last N fingerprints.
 *
 * We compare consecutive pairs (sliding window) rather than all-pairs to keep
 * the computation O(n) instead of O(n²).
 *
 * @param {string[]} fps - array of fingerprints (most recent last)
 * @param {number}   n   - how many to consider
 * @returns {number}
 */
function avgLevenshtein(fps, n) {
  const slice = fps.slice(-n);
  if (slice.length < 2) return Infinity;
  let total = 0;
  for (let i = 1; i < slice.length; i++) {
    total += levenshtein(slice[i - 1], slice[i]);
  }
  return total / (slice.length - 1);
}

// ─── In-Memory Store ────────────────────────────────────────────────────────

// Map<ip, { payloads: string[], timestamps: number[], blocked: boolean, blockedUntil: number }>
const store = new Map();

// Prune entries for IPs not seen in the last 5 minutes
const PRUNE_INTERVAL_MS = 5 * 60 * 1000;
const pruneTimer = setInterval(() => {
  const cutoff = Date.now() - PRUNE_INTERVAL_MS;
  for (const [ip, state] of store) {
    const lastSeen = state.timestamps[state.timestamps.length - 1] || 0;
    if (lastSeen < cutoff) store.delete(ip);
  }
}, PRUNE_INTERVAL_MS);

// Allow the Node.js process to exit even if this timer is active
if (pruneTimer.unref) pruneTimer.unref();

// ─── Middleware Factory ─────────────────────────────────────────────────────

/**
 * Create the mutation tracker middleware.
 *
 * Detects payload FUZZING — an attacker sending many slight variations of the
 * same attack payload to probe WAF bypass opportunities.  Uses Levenshtein
 * distance between normalised fingerprints to detect structural similarity
 * across variants.
 *
 * @param {object} config - WAF configuration (uses config.mutation section)
 * @returns {Function} Express middleware
 */
module.exports = function createMutationTrackerMiddleware(config) {
  const cfg                 = config.mutation || {};
  const windowMs            = cfg.windowMs            || 60_000;
  const maxVariants         = cfg.maxVariants         || 5;
  const levenshteinThreshold = cfg.levenshteinThreshold || 10;
  const replayThreshold     = cfg.replayThreshold     || 10;

  return function mutationTrackerMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    const ip  = req.wafIp || req.ip || req.socket?.remoteAddress || 'unknown';
    const now = Date.now();

    // ── Retrieve or create IP state ──────────────────────────────────────
    if (!store.has(ip)) {
      store.set(ip, { payloads: [], timestamps: [], blocked: false, blockedUntil: 0 });
    }
    const state = store.get(ip);

    // ── Check active block ───────────────────────────────────────────────
    if (state.blocked && now < state.blockedUntil) {
      logBlock({
        logPath:   config.logPath,
        requestId: req.wafRequestId,
        ip,
        method:    req.method,
        path:      req.path,
        rule:      'mutation-active-block',
        matched:   `blocked until ${new Date(state.blockedUntil).toISOString()}`,
        source:    'mutation-tracker',
        severity:  'critical',
        userAgent: req.headers['user-agent'] || '',
      });

      if (config.mode === 'log-only') return next();
      return res.status(403).json({ blocked: true, rule: 'mutation-active-block', message: 'Request blocked by WAF' });
    } else if (state.blocked && now >= state.blockedUntil) {
      // Block expired — reset state
      state.blocked      = false;
      state.blockedUntil = 0;
      state.payloads     = [];
      state.timestamps   = [];
    }

    // ── Extract payload fingerprint ──────────────────────────────────────
    const rawValue = extractSuspiciousValue(req);
    if (!rawValue) return next(); // No suspicious value — nothing to track

    const fp = fingerprint(rawValue);

    // Record this request
    state.payloads.push(fp);
    state.timestamps.push(now);

    // Keep only the last 20 entries
    if (state.payloads.length > 20) {
      state.payloads.shift();
      state.timestamps.shift();
    }

    // ── Rule: Exact Replay ───────────────────────────────────────────────
    // Same fingerprint repeated more than replayThreshold times
    const replayCount = state.payloads.filter((p) => p === fp).length;
    if (replayCount > replayThreshold) {
      const blockUntil = now + 5 * 60 * 1000; // 5-minute block
      state.blocked      = true;
      state.blockedUntil = blockUntil;

      logBlock({
        logPath:   config.logPath,
        requestId: req.wafRequestId,
        ip,
        method:    req.method,
        path:      req.path,
        rule:      'mutation-exact-replay',
        matched:   `fingerprint replayed ${replayCount}x`,
        source:    'mutation-tracker',
        severity:  'high',
        userAgent: req.headers['user-agent'] || '',
      });

      if (config.mode === 'log-only') return next();
      return res.status(403).json({ blocked: true, rule: 'mutation-exact-replay', message: 'Request blocked by WAF' });
    }

    // ── Rule: Fuzzing Detection ──────────────────────────────────────────
    // Need at least maxVariants + 1 samples before analysis
    if (state.payloads.length > maxVariants) {
      // Count unique fingerprints in the last windowMs
      const windowStart       = now - windowMs;
      const recentFps         = state.payloads.filter((_, i) => state.timestamps[i] >= windowStart);
      const uniqueInWindow    = new Set(recentFps).size;

      if (uniqueInWindow > maxVariants) {
        // Check average Levenshtein distance across last 5 fingerprints
        const avgDist = avgLevenshtein(state.payloads, 5);

        if (avgDist < levenshteinThreshold) {
          const blockUntil = now + 10 * 60 * 1000; // 10-minute block
          state.blocked      = true;
          state.blockedUntil = blockUntil;

          logBlock({
            logPath:   config.logPath,
            requestId: req.wafRequestId,
            ip,
            method:    req.method,
            path:      req.path,
            rule:      'mutation-fuzzing',
            matched:   `avgLevenshtein=${avgDist.toFixed(2)} uniqueVariants=${uniqueInWindow} in ${windowMs}ms`,
            source:    'mutation-tracker',
            severity:  'critical',
            userAgent: req.headers['user-agent'] || '',
          });

          if (config.mode === 'log-only') return next();
          return res.status(403).json({ blocked: true, rule: 'mutation-fuzzing', message: 'Request blocked by WAF' });
        }
      }
    }

    next();
  };
};
