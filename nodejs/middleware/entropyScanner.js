'use strict';

const { logBlock } = require('../utils/logger');
const { parseCookies, flattenValues } = require('../utils/patternMatcher');

// ─── Shannon Entropy ────────────────────────────────────────────────────────

/**
 * Compute Shannon entropy of a string.
 * H = -Σ(p_i * log2(p_i)) where p_i = frequency of each unique character.
 *
 * @param {string} str
 * @returns {number} entropy in bits per character (0 = uniform, ~8 = random)
 */
function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  return -Object.values(freq).reduce((sum, count) => {
    const p = count / str.length;
    return sum + p * Math.log2(p);
  }, 0);
}

// ─── Entropy Rules ──────────────────────────────────────────────────────────

/**
 * Evaluate a single string value against all entropy rules.
 * Returns the first matching rule object or null.
 *
 * @param {string} value - Raw parameter value
 * @param {object} cfg   - config.entropy section
 * @returns {{ id: string, severity: string, description: string, entropy: number } | null}
 */
function evaluateEntropy(value, cfg) {
  if (typeof value !== 'string') return null;

  const len = value.length;

  // Skip short values — too short to be meaningful
  if (len < (cfg.minLength || 20)) return null;

  const h = shannonEntropy(value);

  // Rule 1: Near-random entropy → shellcode / binary payload
  if (h > (cfg.shellcodeThreshold || 6.8) && len > 20) {
    return {
      id:          'entropy-shellcode',
      severity:    'critical',
      description: 'Near-random entropy — likely shellcode or binary payload',
      entropy:     h,
    };
  }

  // Rule 2: High entropy over long value → multi-encoded attack payload
  if (h > (cfg.encodedThreshold || 5.5) && len > 50) {
    return {
      id:          'entropy-encoded',
      severity:    'high',
      description: 'High entropy — likely multi-encoded attack payload',
      entropy:     h,
    };
  }

  // Rule 3: Base64-dense block → encoded payload hidden in b64 alphabet
  if (
    h > (cfg.b64Threshold || 5.9) &&
    len > 80 &&
    /^[A-Za-z0-9+/=]+$/.test(value)
  ) {
    return {
      id:          'entropy-b64-block',
      severity:    'high',
      description: 'Base64-dense block — possible encoded payload',
      entropy:     h,
    };
  }

  // Rule 4: Zero entropy over long value → repetitive padding (buffer overflow probe)
  if (h < 0.3 && len > 30) {
    return {
      id:          'entropy-zero',
      severity:    'medium',
      description: 'Zero-entropy padding — possible buffer overflow probe',
      entropy:     h,
    };
  }

  return null;
}

// ─── Source Extraction ──────────────────────────────────────────────────────

/**
 * Extract { source, value } pairs from query params, body, and cookies.
 *
 * @param {object} req - Express request object
 * @returns {Array<{ source: string, value: string }>}
 */
function extractScanTargets(req) {
  const targets = [];

  // Query parameters
  if (req.query && typeof req.query === 'object') {
    for (const [key, raw] of Object.entries(req.query)) {
      for (const val of flattenValues(raw)) {
        targets.push({ source: `query:${key}`, value: val });
      }
    }
  }

  // Request body (parsed object or raw string)
  if (req.body) {
    if (typeof req.body === 'string') {
      targets.push({ source: 'body', value: req.body });
    } else if (typeof req.body === 'object') {
      for (const [key, raw] of Object.entries(req.body)) {
        for (const val of flattenValues(raw)) {
          targets.push({ source: `body:${key}`, value: val });
        }
      }
    }
  }

  // Cookies
  const cookieData =
    req.cookies && typeof req.cookies === 'object'
      ? req.cookies
      : parseCookies(req.headers['cookie'] || '');

  for (const [name, val] of Object.entries(cookieData)) {
    if (typeof val === 'string') {
      targets.push({ source: `cookie:${name}`, value: val });
    }
  }

  return targets;
}

// ─── Middleware Factory ─────────────────────────────────────────────────────

/**
 * Create the entropy scanner middleware.
 *
 * Scans all query params, body values, and cookies for anomalous information
 * density — catching encoded, obfuscated, or binary payloads regardless of
 * their specific content.
 *
 * @param {object} config - WAF configuration (uses config.entropy section)
 * @returns {Function} Express middleware
 */
module.exports = function createEntropyScannerMiddleware(config) {
  const cfg = config.entropy || {};

  return function entropyScannerMiddleware(req, res, next) {
    // Whitelisted / already-trusted requests bypass scanning
    if (req.wafTrusted) return next();

    const ip = req.wafIp || req.ip || req.socket?.remoteAddress || 'unknown';
    const targets = extractScanTargets(req);

    for (const { source, value } of targets) {
      const hit = evaluateEntropy(value, cfg);
      if (!hit) continue;

      // Log the detection
      logBlock({
        logPath:   config.logPath,
        requestId: req.wafRequestId,
        ip,
        method:    req.method,
        path:      req.path,
        rule:      hit.id,
        matched:   `entropy=${hit.entropy.toFixed(3)} len=${value.length}`,
        source,
        severity:  hit.severity,
        userAgent: req.headers['user-agent'] || '',
      });

      // In log-only mode let the request continue
      if (config.mode === 'log-only') return next();

      return res.status(403).json({
        blocked: true,
        rule:    hit.id,
        message: 'Request blocked by WAF',
      });
    }

    next();
  };
};
