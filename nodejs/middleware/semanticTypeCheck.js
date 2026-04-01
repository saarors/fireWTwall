'use strict';

const { logBlock } = require('../utils/logger');

// ─── Semantic Type Sets ─────────────────────────────────────────────────────

/**
 * Parameter names that are expected to carry purely numeric values.
 * Any injection character in these params is immediately suspicious.
 */
const NUMERIC_PARAMS = new Set([
  'id','ids','uid','pid','gid','tid','sid','cid','fid','aid','bid',
  'page','pages','limit','offset','size','count','total','num','number',
  'age','year','month','day','hour','minute','second',
  'qty','quantity','amount','price','cost','fee','tax','discount',
  'score','rank','rating','vote','likes','views','hits',
  'width','height','depth','length','weight',
  'port','timeout','retries','version','rev','step',
]);

/**
 * Parameter names that should carry safe, simple strings — alphanumeric
 * plus basic punctuation.  Injection metacharacters or very long values are
 * suspicious here.
 */
const SAFE_STRING_PARAMS = new Set([
  'name','username','user','firstname','lastname','fullname',
  'title','label','tag','category','type','format','lang','locale',
  'status','state','action','method','mode','theme','color','size',
  'country','city','zip','code','currency',
]);

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Characters that have no business appearing in numeric/ID fields */
const INJECTION_CHARS_NUMERIC = /[<>'"`;()|\\%]/;

/** A broader set for safe-string fields */
const INJECTION_CHARS_STRING  = /[<>'";\(\)|\\%${}]/;

/** Pure integer (with optional leading minus) */
const RE_INTEGER = /^-?\d+$/;

/**
 * UUID v1–v5 pattern (case-insensitive).
 * Allows IDs like "550e8400-e29b-41d4-a716-446655440000"
 */
const RE_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Return true when `value` is a valid integer string or a UUID.
 *
 * @param {string} value
 * @returns {boolean}
 */
function isNumericOrUuid(value) {
  return RE_INTEGER.test(value) || RE_UUID.test(value);
}

// ─── Parameter Pollution Count ──────────────────────────────────────────────

/**
 * Count how many times each query-string key appears by parsing req.url
 * directly.  We cannot rely on req.query because Express (and most parsers)
 * collapse duplicate keys into arrays, losing the raw count.
 *
 * @param {object} req
 * @returns {Map<string, number>}
 */
function countRawQueryParams(req) {
  const counts = new Map();
  try {
    const qs = (req.url || '').split('?')[1] || '';
    if (!qs) return counts;

    for (const pair of qs.split('&')) {
      const eqIdx = pair.indexOf('=');
      const key   = eqIdx >= 0 ? pair.slice(0, eqIdx) : pair;
      if (!key) continue;
      // Decode the key in case it's percent-encoded
      let decoded;
      try { decoded = decodeURIComponent(key); } catch { decoded = key; }
      counts.set(decoded, (counts.get(decoded) || 0) + 1);
    }
  } catch {
    // Malformed URL — ignore
  }
  return counts;
}

// ─── Core Check ─────────────────────────────────────────────────────────────

/**
 * Test a single (paramName, value) pair against all semantic rules.
 * Returns a rule hit or null.
 *
 * @param {string} paramName
 * @param {string} value
 * @returns {{ id: string, severity: string, detail: string } | null}
 */
function checkParam(paramName, value) {
  if (typeof value !== 'string') return null;
  const lower = paramName.toLowerCase();

  // ── Rule 1: Numeric param contains injection chars ─────────────────────
  if (NUMERIC_PARAMS.has(lower) && INJECTION_CHARS_NUMERIC.test(value)) {
    return {
      id:       'semantic-numeric-attack',
      severity: 'high',
      detail:   `numeric param "${paramName}" contains injection character`,
    };
  }

  // ── Rule 2: Safe-string param contains injection chars or is too long ──
  if (SAFE_STRING_PARAMS.has(lower)) {
    if (value.length > 200 || INJECTION_CHARS_STRING.test(value)) {
      return {
        id:       'semantic-string-attack',
        severity: 'high',
        detail:   value.length > 200
          ? `safe-string param "${paramName}" value length ${value.length} > 200`
          : `safe-string param "${paramName}" contains injection character`,
      };
    }
  }

  // ── Rule 3: ID param contains non-numeric / non-UUID value ────────────
  // Covers: paramName === 'id'  OR  paramName ends with '_id' or 'Id'
  const isIdParam =
    lower === 'id' ||
    paramName.endsWith('_id') ||
    paramName.endsWith('Id');

  if (isIdParam && !isNumericOrUuid(value)) {
    return {
      id:       'semantic-id-injection',
      severity: 'high',
      detail:   `ID param "${paramName}" value is not an integer or UUID: "${value.slice(0, 80)}"`,
    };
  }

  return null;
}

// ─── Middleware Factory ─────────────────────────────────────────────────────

/**
 * Create the semantic type-check middleware.
 *
 * Detects type-confusion attacks: parameters that should be numbers, dates,
 * or simple identifiers suddenly containing SQL, code, or special characters.
 * Also detects HTTP parameter pollution (same param > 50 times).
 *
 * @param {object} config - WAF configuration
 * @returns {Function} Express middleware
 */
module.exports = function createSemanticTypeCheckMiddleware(config) {

  return function semanticTypeCheckMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    const ip = req.wafIp || req.ip || req.socket?.remoteAddress || 'unknown';

    // ── Rule 4: HTTP Parameter Pollution (array bomb) ────────────────────
    // Count raw occurrences of each query-string key BEFORE Express collapses them
    const rawCounts = countRawQueryParams(req);
    for (const [key, count] of rawCounts) {
      if (count > 50) {
        logBlock({
          logPath:   config.logPath,
          requestId: req.wafRequestId,
          ip,
          method:    req.method,
          path:      req.path,
          rule:      'semantic-array-bomb',
          matched:   `param "${key}" appears ${count} times`,
          source:    'query',
          severity:  'critical',
          userAgent: req.headers['user-agent'] || '',
        });

        if (config.mode === 'log-only') return next();
        return res.status(403).json({ blocked: true, rule: 'semantic-array-bomb', message: 'Request blocked by WAF' });
      }
    }

    // ── Rules 1–3: Per-parameter type checks ────────────────────────────

    // Collect (name, value) pairs from query and body
    const pairs = [];

    if (req.query && typeof req.query === 'object') {
      for (const [key, raw] of Object.entries(req.query)) {
        const vals = Array.isArray(raw) ? raw : [raw];
        for (const v of vals) {
          if (typeof v === 'string') pairs.push({ name: key, value: v, source: 'query' });
        }
      }
    }

    if (req.body && typeof req.body === 'object' && !Array.isArray(req.body)) {
      for (const [key, raw] of Object.entries(req.body)) {
        const vals = Array.isArray(raw) ? raw : [raw];
        for (const v of vals) {
          if (typeof v === 'string') pairs.push({ name: key, value: v, source: 'body' });
        }
      }
    }

    for (const { name, value, source } of pairs) {
      const hit = checkParam(name, value);
      if (!hit) continue;

      logBlock({
        logPath:   config.logPath,
        requestId: req.wafRequestId,
        ip,
        method:    req.method,
        path:      req.path,
        rule:      hit.id,
        matched:   hit.detail,
        source,
        severity:  hit.severity,
        userAgent: req.headers['user-agent'] || '',
      });

      if (config.mode === 'log-only') return next();
      return res.status(403).json({ blocked: true, rule: hit.id, message: 'Request blocked by WAF' });
    }

    next();
  };
};
