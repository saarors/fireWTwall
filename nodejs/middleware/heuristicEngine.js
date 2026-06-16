'use strict';

const { logBlock } = require('../utils/logger');
const { parseCookies, flattenValues } = require('../utils/patternMatcher');

// ─────────────────────────────────────────────
// Attack keywords
// ─────────────────────────────────────────────

const ATTACK_KEYWORDS = [
  'select','union','insert','delete','update','drop','exec','eval',
  'alert','script','onerror','onload','system','passthru','popen',
  'cmd','bash','wget','curl','chmod',
];

const KEYWORD_SET = new Set(ATTACK_KEYWORDS);

// ─────────────────────────────────────────────
// Safe helpers
// ─────────────────────────────────────────────

function safeString(v) {
  if (typeof v !== 'string') return '';
  return v.trim();
}

function clampLength(v, max = 5000) {
  if (v.length > max) return v.slice(0, max);
  return v;
}

// ─────────────────────────────────────────────
// Rule 1 — Encoding Mix (optimized: early exit)
// ─────────────────────────────────────────────

function hasEncodingMix(value, threshold) {
  let count = 0;

  if (/%[0-9a-fA-F]{2}/.test(value)) count++;
  if (/(&[a-z]+;|&#[0-9]+;)/.test(value)) count++;
  if /(0x[0-9a-fA-F]+|\\x[0-9a-fA-F]{2})/.test(value) count++;
  if /(\\u[0-9a-fA-F]{4}|%u[0-9a-fA-F]{4})/.test(value) count++;
  if (/[A-Za-z0-9+/]{16,}={0,2}/.test(value)) count++;

  return count >= threshold;
}

// ─────────────────────────────────────────────
// Rule 2 — Nesting Depth (safe linear scan)
// ─────────────────────────────────────────────

function hasDeepNesting(value, threshold) {
  let depth = 0;
  let maxDepth = 0;

  for (let i = 0; i < value.length; i++) {
    const ch = value[i];

    if (ch === '(' || ch === '{' || ch === '[' || ch === '<') {
      depth++;
      if (depth > maxDepth) maxDepth = depth;
      if (maxDepth > threshold) return true;
    } else if (ch === ')' || ch === '}' || ch === ']' || ch === '>') {
      depth = Math.max(0, depth - 1);
    }
  }

  return false;
}

// ─────────────────────────────────────────────
// Rule 3 — Keyword Density (sliding window safe)
// ─────────────────────────────────────────────

function hasHighKeywordDensity(value, threshold) {
  const lower = value.toLowerCase();

  let count = 0;

  for (const kw of KEYWORD_SET) {
    let idx = 0;

    while ((idx = lower.indexOf(kw, idx)) !== -1) {
      count++;
      idx += kw.length;

      if (count > 50) break; // hard cap for safety
    }
  }

  const density = (count / Math.max(lower.length, 1)) * 100;
  return density > threshold;
}

// ─────────────────────────────────────────────
// Rule 4 — Function Chain (regex hardened)
// ─────────────────────────────────────────────

function hasFunctionChain(value) {
  // bounded repetition to avoid ReDoS
  return /\w+\s*\([^()]{0,50}\w+\s*\([^()]{0,50}\w+\s*\(/.test(value);
}

// ─────────────────────────────────────────────
// Rule 5 — Operator Storm (single-pass safe)
// ─────────────────────────────────────────────

const OPERATORS = new Set([
  '--','/*','*/','"',"'",'`','=','<','>','|','&',';'
]);

function hasOperatorStorm(value, threshold) {
  let count = 0;
  let i = 0;
  const len = value.length;

  while (i < len) {
    let matched = false;

    for (const op of OPERATORS) {
      if (value.startsWith(op, i)) {
        count++;
        i += op.length;
        matched = true;

        if (count > 100) return true; // hard cap

        break;
      }
    }

    if (!matched) i++;
  }

  const density = (count / len) * 100;
  return density > threshold;
}

// ─────────────────────────────────────────────
// Rule 6 — Polyglot detection (safe)
// ─────────────────────────────────────────────

function isPolyglot(value) {
  let fires = 0;

  if (/\b(select|union|insert)\b/i.test(value)) fires++;
  if (/(script|alert|eval)/i.test(value)) fires++;
  if (/[|;]|&&|\bexec\b/.test(value)) fires++;

  return fires >= 3;
}

// ─────────────────────────────────────────────
// Target extraction (hardened)
// ─────────────────────────────────────────────

function extractTargets(req) {
  const targets = [];

  function push(source, raw) {
    for (const v of flattenValues(raw)) {
      const str = safeString(v);
      if (!str || str.length < 1) continue;
      targets.push({ source, value: clampLength(str) });
    }
  }

  if (req.query && typeof req.query === 'object') {
    for (const [key, raw] of Object.entries(req.query)) {
      push(`query:${key}`, raw);
    }
  }

  if (req.body) {
    if (typeof req.body === 'string') {
      push('body', req.body);
    } else if (typeof req.body === 'object') {
      for (const [key, raw] of Object.entries(req.body)) {
        push(`body:${key}`, raw);
      }
    }
  }

  const cookies =
    req.cookies && typeof req.cookies === 'object'
      ? req.cookies
      : parseCookies(req.headers?.cookie || '');

  for (const [name, val] of Object.entries(cookies)) {
    if (typeof val === 'string') {
      push(`cookie:${name}`, val);
    }
  }

  return targets;
}

// ─────────────────────────────────────────────
// Middleware
// ─────────────────────────────────────────────

module.exports = function createHeuristicEngineMiddleware(config) {
  const cfg = config.heuristic || {};

  const encodingMixThreshold    = cfg.encodingMixThreshold   || 3;
  const nestingDepthThreshold   = cfg.nestingDepthThreshold  || 6;
  const keywordDensityThreshold = cfg.keywordDensityThreshold || 3;
  const operatorStormThreshold  = cfg.operatorStormThreshold || 15;

  const MIN_LEN = 15;

  return function heuristicEngineMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    const ip = req.wafIp || req.ip || req.socket?.remoteAddress || 'unknown';
    const targets = extractTargets(req);

    for (const { source, value } of targets) {
      if (value.length < MIN_LEN) continue;

      let ruleId = null;
      let severity = 'high';
      let detail = '';

      if (isPolyglot(value)) {
        ruleId = 'heuristic-polyglot';
        severity = 'critical';
        detail = 'multi-category attack pattern detected';
      }
      else if (hasEncodingMix(value, encodingMixThreshold)) {
        ruleId = 'heuristic-encoding-mix';
        severity = 'critical';
        detail = 'multiple encoding types detected';
      }
      else if (hasDeepNesting(value, nestingDepthThreshold)) {
        ruleId = 'heuristic-deep-nesting';
        detail = 'deep bracket nesting detected';
      }
      else if (hasHighKeywordDensity(value, keywordDensityThreshold)) {
        ruleId = 'heuristic-keyword-density';
        detail = 'high keyword density detected';
      }
      else if (hasFunctionChain(value)) {
        ruleId = 'heuristic-function-chain';
        detail = 'nested function chain detected';
      }
      else if (hasOperatorStorm(value, operatorStormThreshold)) {
        ruleId = 'heuristic-operator-storm';
        detail = 'high operator density detected';
      }

      if (!ruleId) continue;

      logBlock({
        logPath: config.logPath,
        requestId: req.wafRequestId,
        ip,
        method: req.method,
        path: req.path,
        rule: ruleId,
        matched: detail,
        source,
        severity,
        userAgent: req.headers['user-agent'] || '',
      });

      if (config.mode === 'log-only') return next();

      return res.status(403).json({
        blocked: true,
        rule: ruleId,
        message: 'Request blocked by WAF',
      });
    }

    next();
  };
};
