'use strict';

const { logBlock } = require('../utils/logger');
const { parseCookies, flattenValues } = require('../utils/patternMatcher');

// ─── Attack keywords for keyword-density rule ───────────────────────────────

const ATTACK_KEYWORDS = [
  'select','union','insert','delete','update','drop','exec','eval',
  'alert','script','onerror','onload','system','passthru','popen',
  'cmd','bash','wget','curl','chmod',
];

// ─── Rule implementations ───────────────────────────────────────────────────

/**
 * Rule 1 — Encoding Density
 * Count how many DISTINCT encoding types appear in a single value.
 * Attacking via mixed encodings is a classic WAF-bypass technique.
 *
 * @param {string} value
 * @param {number} threshold - distinct types needed to trigger
 * @returns {boolean}
 */
function hasEncodingMix(value, threshold) {
  const patterns = [
    /(%[0-9a-fA-F]{2})/,                    // URL encoding
    /(&[a-z]+;|&#[0-9]+;)/,                  // HTML entities
    /(0x[0-9a-fA-F]+|\\x[0-9a-fA-F]{2})/,   // Hex literals
    /(\\u[0-9a-fA-F]{4}|%u[0-9a-fA-F]{4})/, // Unicode escapes
    /([A-Za-z0-9+/]{16,}={0,2})/,           // Base64-like blocks
  ];
  let distinctCount = 0;
  for (const p of patterns) {
    if (p.test(value)) distinctCount++;
  }
  return distinctCount >= threshold;
}

/**
 * Rule 2 — Nesting Depth
 * Track the deepest combined nesting of (), {}, [], <> brackets.
 * Deeply nested structures are a fingerprint of obfuscated code / polyglots.
 *
 * @param {string} value
 * @param {number} threshold
 * @returns {boolean}
 */
function hasDeepNesting(value, threshold) {
  const open  = new Set(['(', '{', '[', '<']);
  const close = new Set([')', '}', ']', '>']);
  let depth = 0;
  let maxDepth = 0;

  for (const ch of value) {
    if (open.has(ch))  { depth++; if (depth > maxDepth) maxDepth = depth; }
    if (close.has(ch)) { depth = Math.max(0, depth - 1); }
  }
  return maxDepth > threshold;
}

/**
 * Rule 3 — Keyword Density
 * High concentration of attack-related keywords per 100 characters.
 *
 * @param {string} value
 * @param {number} threshold - occurrences per 100 chars
 * @returns {boolean}
 */
function hasHighKeywordDensity(value, threshold) {
  if (value.length === 0) return false;
  const lower = value.toLowerCase();
  let count = 0;
  for (const kw of ATTACK_KEYWORDS) {
    let idx = 0;
    while ((idx = lower.indexOf(kw, idx)) !== -1) {
      count++;
      idx += kw.length;
    }
  }
  return (count / value.length * 100) > threshold;
}

/**
 * Rule 4 — Function Chain Depth
 * Triple+ chained function calls: a(b(c( ... )))
 * Regex detects at least three levels of call nesting.
 *
 * @param {string} value
 * @returns {boolean}
 */
function hasFunctionChain(value) {
  return /\w+\s*\([^)]*\w+\s*\([^)]*\w+\s*\(/.test(value);
}

/**
 * Rule 5 — Operator Storm
 * Excessive density of attack-related operators signals injected syntax.
 *
 * @param {string} value
 * @param {number} threshold - operators per 100 chars
 * @returns {boolean}
 */
function hasOperatorStorm(value, threshold) {
  if (value.length === 0) return false;
  // Count each operator token individually
  const tokens = ['--', '/*', '*/', "\"", "'", '`', '=', '<', '>', '|', '&', ';'];
  let count = 0;
  // Work through the string once
  let i = 0;
  while (i < value.length) {
    let matched = false;
    for (const tok of tokens) {
      if (value.startsWith(tok, i)) {
        count++;
        i += tok.length;
        matched = true;
        break;
      }
    }
    if (!matched) i++;
  }
  return (count / value.length * 100) > threshold;
}

/**
 * Rule 6 — Polyglot Detector
 * A value that simultaneously satisfies patterns from 3+ attack categories
 * is almost certainly a polyglot payload designed to bypass category-specific
 * filters.
 *
 * @param {string} value
 * @returns {boolean}
 */
function isPolyglot(value) {
  const categories = [
    { name: 'sql',   pattern: /\b(select|union|insert)\b/i },
    { name: 'js',    pattern: /(script|alert|eval)/i },
    { name: 'shell', pattern: /[|;]|&&|\bexec\b/ },
  ];
  let fires = 0;
  for (const cat of categories) {
    if (cat.pattern.test(value)) fires++;
  }
  return fires >= 3;
}

// ─── Source Extraction ──────────────────────────────────────────────────────

/**
 * Flatten all query params, body values, and cookies into
 * { source, value } pairs.
 *
 * @param {object} req
 * @returns {Array<{ source: string, value: string }>}
 */
function extractTargets(req) {
  const targets = [];

  if (req.query && typeof req.query === 'object') {
    for (const [key, raw] of Object.entries(req.query)) {
      for (const v of flattenValues(raw)) targets.push({ source: `query:${key}`, value: v });
    }
  }

  if (req.body) {
    if (typeof req.body === 'string') {
      targets.push({ source: 'body', value: req.body });
    } else if (typeof req.body === 'object') {
      for (const [key, raw] of Object.entries(req.body)) {
        for (const v of flattenValues(raw)) targets.push({ source: `body:${key}`, value: v });
      }
    }
  }

  const cookies =
    req.cookies && typeof req.cookies === 'object'
      ? req.cookies
      : parseCookies(req.headers['cookie'] || '');

  for (const [name, val] of Object.entries(cookies)) {
    if (typeof val === 'string') targets.push({ source: `cookie:${name}`, value: val });
  }

  return targets;
}

// ─── Middleware Factory ─────────────────────────────────────────────────────

/**
 * Create the heuristic engine middleware.
 *
 * Detects zero-day and novel attack patterns based on STRUCTURAL analysis —
 * encoding mix, nesting depth, keyword density, function chains, operator
 * storms, and polyglot detection — independent of any known signature.
 *
 * @param {object} config - WAF configuration (uses config.heuristic section)
 * @returns {Function} Express middleware
 */
module.exports = function createHeuristicEngineMiddleware(config) {
  const cfg = config.heuristic || {};
  const encodingMixThreshold   = cfg.encodingMixThreshold   || 3;
  const nestingDepthThreshold  = cfg.nestingDepthThreshold  || 6;
  const keywordDensityThreshold = cfg.keywordDensityThreshold || 3;
  const operatorStormThreshold  = cfg.operatorStormThreshold  || 15;

  // Minimum value length — very short strings are not useful to analyze
  const MIN_LEN = 15;

  return function heuristicEngineMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    const ip      = req.wafIp || req.ip || req.socket?.remoteAddress || 'unknown';
    const targets = extractTargets(req);

    for (const { source, value } of targets) {
      if (typeof value !== 'string' || value.length < MIN_LEN) continue;

      let ruleId   = null;
      let severity = 'high';
      let detail   = '';

      // ── Rule 6 first (critical, highest priority) ────────────────────────
      if (isPolyglot(value)) {
        ruleId   = 'heuristic-polyglot';
        severity = 'critical';
        detail   = 'payload matches SQL + JS + shell patterns simultaneously';
      }
      // ── Rule 1: Encoding mix ─────────────────────────────────────────────
      else if (hasEncodingMix(value, encodingMixThreshold)) {
        ruleId   = 'heuristic-encoding-mix';
        severity = 'critical';
        detail   = `≥${encodingMixThreshold} distinct encoding types in single value`;
      }
      // ── Rule 2: Nesting depth ────────────────────────────────────────────
      else if (hasDeepNesting(value, nestingDepthThreshold)) {
        ruleId = 'heuristic-deep-nesting';
        detail = `bracket nesting depth > ${nestingDepthThreshold}`;
      }
      // ── Rule 3: Keyword density ──────────────────────────────────────────
      else if (hasHighKeywordDensity(value, keywordDensityThreshold)) {
        ruleId = 'heuristic-keyword-density';
        detail = `keyword density > ${keywordDensityThreshold} per 100 chars`;
      }
      // ── Rule 4: Function chain depth ─────────────────────────────────────
      else if (hasFunctionChain(value)) {
        ruleId = 'heuristic-function-chain';
        detail = 'triple+ nested function call chain detected';
      }
      // ── Rule 5: Operator storm ───────────────────────────────────────────
      else if (hasOperatorStorm(value, operatorStormThreshold)) {
        ruleId = 'heuristic-operator-storm';
        detail = `operator density > ${operatorStormThreshold} per 100 chars`;
      }

      if (!ruleId) continue;

      logBlock({
        logPath:   config.logPath,
        requestId: req.wafRequestId,
        ip,
        method:    req.method,
        path:      req.path,
        rule:      ruleId,
        matched:   detail,
        source,
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

    next();
  };
};
