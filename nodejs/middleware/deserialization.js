'use strict';

const { scanSources } = require('../utils/patternMatcher');
const { logBlock }    = require('../utils/logger');

// ── Deserialization attack rules ───────────────────────────────────────────────
// Covers PHP object/array serialization, Java serialized objects (binary magic
// bytes as both base64 and hex), Python pickle payloads, and the well-known
// node-serialize RCE gadget.
const DESER_RULES = [
  // ── PHP ───────────────────────────────────────────────────────────────────
  { name: 'deser-php-object',     severity: 'critical', pattern: /O:\d+:"[a-zA-Z_\\]+"\s*:\d+:\s*\{/,          description: 'PHP serialized object injection' },
  { name: 'deser-php-array',      severity: 'high',     pattern: /a:\d+:\{(?:i:\d+;|s:\d+:")/,                 description: 'PHP serialized array injection' },

  // ── Java ──────────────────────────────────────────────────────────────────
  // Base64-encoded Java serialized stream starts with AC ED 00 05 → rO0AB
  { name: 'deser-java-b64',       severity: 'critical', pattern: /rO0AB[XY]/,                                   description: 'Java serialized object (base64 AC ED)' },
  // Raw hex magic bytes
  { name: 'deser-java-hex',       severity: 'critical', pattern: /aced0005/i,                                   description: 'Java serialized object (hex magic)' },

  // ── Python pickle ─────────────────────────────────────────────────────────
  // Protocol header byte followed by protocol version 1-5 (0x80 0x01–0x05)
  { name: 'deser-python-pickle',  severity: 'critical', pattern: /\x80[\x01-\x05]|\(dp\d+\n|cos\nsystem\n/,    description: 'Python pickle payload' },
  // Common base64-encoded pickle protocol 4 / protocol 2 prefixes
  { name: 'deser-python-b64pick', severity: 'high',     pattern: /gASV|gAJ[TU]/,                                description: 'Python pickle (base64 protocol 4/2)' },

  // ── Node.js ───────────────────────────────────────────────────────────────
  { name: 'deser-node-serialize', severity: 'critical', pattern: /\{"rce"\s*:\s*"_\$\$ND_FUNC\$\$_function/i,  description: 'node-serialize RCE payload' },
];

/**
 * Deserialization middleware — scans query params, parsed body, raw body
 * (req.rawBody if set by a bodyParser), and cookies for serialized object
 * payloads from PHP, Java, Python pickle, and Node.js.
 *
 * @param {object} config - WAF configuration
 * @returns {Function} Express middleware
 */
function createDeserializationMiddleware(config) {
  return function deserializationMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    const sources = [
      { label: 'query',   data: req.query },
      { label: 'body',    data: req.body },
      { label: 'cookies', data: req.cookies },
    ];

    // Also check the raw (un-parsed) body string if a bodyParser has exposed it
    if (typeof req.rawBody === 'string' && req.rawBody.length > 0) {
      sources.push({ label: 'body-raw', data: req.rawBody });
    }

    const hit = scanSources(sources, DESER_RULES);

    if (hit) {
      const ip      = req.wafIp || req.socket?.remoteAddress || 'unknown';
      const ruleDef = DESER_RULES.find((r) => r.name === hit.rule);

      logBlock({
        logPath:   config.logPath,
        ip,
        method:    req.method,
        path:      req.path,
        rule:      hit.rule,
        matched:   hit.matched,
        source:    hit.source,
        severity:  ruleDef?.severity || 'critical',
        userAgent: req.headers['user-agent'] || '',
      });

      if (config.mode === 'log-only') return next();

      return res.status(403).json({
        blocked: true,
        rule:    hit.rule,
        message: 'Request blocked by WAF',
      });
    }

    next();
  };
}

module.exports = createDeserializationMiddleware;
