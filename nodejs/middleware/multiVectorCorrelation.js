'use strict';

const { logBlock } = require('../utils/logger');
const { parseCookies, flattenValues } = require('../utils/patternMatcher');

// ─── Fragment Patterns ──────────────────────────────────────────────────────
//
// These are LIGHTWEIGHT partial-match patterns — intentionally broad.
// Each one catches fragments of a larger attack category.  They are not
// full attack signatures (those live in the dedicated middleware).  The
// value here is correlation: any single fragment in isolation is noise;
// the same fragment spread across 3+ separate parameters is signal.

const FRAGMENTS = {
  sql:     /\b(select|union|from|where|having|order|group|insert|update|delete|drop)\b/i,
  xss:     /<[a-z]|javascript:|on[a-z]+\s*=|eval\s*\(/i,
  shell:   /[|;&`$]|\.\//,
  path:    /\.\.[/\\]|\/etc\/|\/proc\//,
  encode:  /%[0-9a-f]{2}|&#x?[0-9a-f]+;|\\x[0-9a-f]{2}/i,
  quote:   /['"`]/,
  comment: /\/\*|--\s|#\s*$|\/\//,
};

// ─── Source Extraction ──────────────────────────────────────────────────────

/**
 * Extract { paramKey, value } entries from all incoming data surfaces.
 * Each entry represents one discrete parameter — the key is used to
 * identify SEPARATE params (so the same value in the same key counted once).
 *
 * @param {object} req
 * @returns {Array<{ paramKey: string, value: string }>}
 */
function extractParamEntries(req) {
  const entries = [];

  // Query string parameters
  if (req.query && typeof req.query === 'object') {
    for (const [key, raw] of Object.entries(req.query)) {
      for (const v of flattenValues(raw)) {
        entries.push({ paramKey: `query:${key}`, value: v });
      }
    }
  }

  // Body parameters
  if (req.body) {
    if (typeof req.body === 'string') {
      entries.push({ paramKey: 'body', value: req.body });
    } else if (typeof req.body === 'object') {
      for (const [key, raw] of Object.entries(req.body)) {
        for (const v of flattenValues(raw)) {
          entries.push({ paramKey: `body:${key}`, value: v });
        }
      }
    }
  }

  // Cookies
  const cookies =
    req.cookies && typeof req.cookies === 'object'
      ? req.cookies
      : parseCookies(req.headers['cookie'] || '');

  for (const [name, val] of Object.entries(cookies)) {
    if (typeof val === 'string') {
      entries.push({ paramKey: `cookie:${name}`, value: val });
    }
  }

  return entries;
}

// ─── Correlation Logic ──────────────────────────────────────────────────────

/**
 * For each fragment category, collect the distinct parameter keys that match.
 * Returns a Map<category, Set<paramKey>>.
 *
 * Using distinct paramKey (not value) ensures we count separate parameters,
 * not repeated occurrences in the same parameter.
 *
 * @param {Array<{ paramKey: string, value: string }>} entries
 * @returns {Map<string, Set<string>>}
 */
function buildCategoryMap(entries) {
  const map = new Map();
  for (const cat of Object.keys(FRAGMENTS)) map.set(cat, new Set());

  for (const { paramKey, value } of entries) {
    if (typeof value !== 'string' || value.length === 0) continue;
    for (const [cat, pattern] of Object.entries(FRAGMENTS)) {
      if (pattern.test(value)) {
        map.get(cat).add(paramKey);
      }
    }
  }

  return map;
}

// ─── Middleware Factory ─────────────────────────────────────────────────────

/**
 * Create the multi-vector correlation middleware.
 *
 * This middleware runs LAST in the chain so it can see all parameters at once.
 * It detects SPLIT injection attacks — where a payload is divided across
 * multiple parameters, each individually harmless, but collectively revealing
 * attacker intent.
 *
 * @param {object} config - WAF configuration
 * @returns {Function} Express middleware
 */
module.exports = function createMultiVectorCorrelationMiddleware(config) {

  return function multiVectorCorrelationMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    const ip      = req.wafIp || req.ip || req.socket?.remoteAddress || 'unknown';
    const entries = extractParamEntries(req);

    // Nothing to correlate when there are fewer than 3 params
    if (entries.length < 3) return next();

    const catMap = buildCategoryMap(entries);

    let ruleId   = null;
    let severity = 'critical';
    let detail   = '';

    // ── Rule 1: SQL fragments spread across 3+ separate params ───────────
    if (!ruleId && catMap.get('sql').size >= 3) {
      ruleId = 'correlation-split-sql';
      detail = `SQL fragments in ${catMap.get('sql').size} separate params: ${[...catMap.get('sql')].join(', ')}`;
    }

    // ── Rule 2: XSS fragments spread across 3+ separate params ──────────
    if (!ruleId && catMap.get('xss').size >= 3) {
      ruleId = 'correlation-split-xss';
      detail = `XSS fragments in ${catMap.get('xss').size} separate params: ${[...catMap.get('xss')].join(', ')}`;
    }

    // ── Rule 3: 4+ different attack categories active simultaneously ─────
    // Full-spectrum probe: attacker is testing every attack surface at once.
    if (!ruleId) {
      const activeCats = [...catMap.entries()]
        .filter(([, keys]) => keys.size >= 1)
        .map(([cat]) => cat);

      if (activeCats.length >= 4) {
        ruleId = 'correlation-mixed-vectors';
        detail = `${activeCats.length} attack categories active simultaneously: ${activeCats.join(', ')}`;
      }
    }

    // ── Rule 4: Quote characters in 3+ separate params ──────────────────
    // Multi-param injection setup — attacker is probing injection points.
    if (!ruleId && catMap.get('quote').size >= 3) {
      ruleId   = 'correlation-quote-injection';
      severity = 'high';
      detail   = `Quote characters in ${catMap.get('quote').size} separate params: ${[...catMap.get('quote')].join(', ')}`;
    }

    if (!ruleId) return next();

    logBlock({
      logPath:   config.logPath,
      requestId: req.wafRequestId,
      ip,
      method:    req.method,
      path:      req.path,
      rule:      ruleId,
      matched:   detail,
      source:    'multi-param',
      severity,
      userAgent: req.headers['user-agent'] || '',
    });

    if (config.mode === 'log-only') return next();

    return res.status(403).json({
      blocked: true,
      rule:    ruleId,
      message: 'Request blocked by WAF',
    });
  };
};
