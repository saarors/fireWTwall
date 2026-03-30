'use strict';

const { scanSources } = require('../utils/patternMatcher');
const { logBlock } = require('../utils/logger');

const XSS_RULES = [
  // ── Critical ───────────────────────────────────────────────────────────
  { name: 'xss-script-tag',       severity: 'critical', pattern: /<\s*script[\s>\/]/i },
  { name: 'xss-javascript-proto', severity: 'critical', pattern: /javascript\s*:/i },
  { name: 'xss-vbscript-proto',   severity: 'critical', pattern: /vbscript\s*:/i },
  { name: 'xss-data-uri',         severity: 'critical', pattern: /data\s*:\s*text\/html/i },

  // ── High ───────────────────────────────────────────────────────────────
  { name: 'xss-event-handler',    severity: 'high',     pattern: /\bon\w+\s*=/i },
  { name: 'xss-iframe',           severity: 'high',     pattern: /<\s*iframe[\s>\/]/i },
  { name: 'xss-object-embed',     severity: 'high',     pattern: /<\s*(?:object|embed)[\s>\/]/i },
  { name: 'xss-svg',              severity: 'high',     pattern: /<\s*svg[\s>\/]/i },
  { name: 'xss-expression',       severity: 'high',     pattern: /expression\s*\(/i },
  { name: 'xss-srcdoc',           severity: 'high',     pattern: /srcdoc\s*=/i },
  { name: 'xss-form-action',      severity: 'high',     pattern: /<\s*form[^>]+action\s*=\s*['"]?javascript/i },
  { name: 'xss-dom-write',        severity: 'high',     pattern: /document\s*\.\s*(?:write|writeln)\s*\(/i },
  { name: 'xss-inner-html',       severity: 'high',     pattern: /\.innerHTML\s*=/i },
  { name: 'xss-location-href',    severity: 'high',     pattern: /(?:window\.|document\.)?location\s*(?:\.\s*href)?\s*=\s*['"]?javascript/i },
  { name: 'xss-angularjs-bind',   severity: 'high',     pattern: /\{\{.*\}\}/ },

  // ── Medium ─────────────────────────────────────────────────────────────
  { name: 'xss-link-meta',        severity: 'medium',   pattern: /<\s*(?:link|meta)[\s>\/]/i },
  { name: 'xss-img-src',          severity: 'medium',   pattern: /<\s*img[^>]+src\s*=/i },
  { name: 'xss-style-attr',       severity: 'medium',   pattern: /style\s*=\s*['"][^'"]*(?:expression|url|javascript)/i },
  { name: 'xss-base-href',        severity: 'medium',   pattern: /<\s*base[\s>]/i },
  { name: 'xss-html-import',      severity: 'medium',   pattern: /<\s*(?:import|template)[\s>\/]/i },
  { name: 'xss-template-literal', severity: 'medium',   pattern: /`[^`]*\$\{[^}]*\}[^`]*`/ },

  // ── New rules (v2) ─────────────────────────────────────────────────────
  { name: 'xss-css-import',       severity: 'high',     pattern: /@import\s+url\s*\(/i,                                description: 'CSS @import injection' },
  { name: 'xss-moz-binding',      severity: 'high',     pattern: /-moz-binding\s*:/i,                                  description: 'Firefox -moz-binding XSS' },
  { name: 'xss-meta-refresh',     severity: 'high',     pattern: /<meta[^>]+http-equiv\s*=\s*["']?refresh/i,           description: 'Meta refresh redirect' },
  { name: 'xss-form-action-js',   severity: 'high',     pattern: /<form[^>]+action\s*=\s*["']?javascript/i,            description: 'Form action javascript XSS' },
  { name: 'xss-link-import',      severity: 'high',     pattern: /<link[^>]+rel\s*=\s*["']?import/i,                   description: 'HTML import injection' },
  { name: 'xss-svg-animate',      severity: 'medium',   pattern: /<animate[^>]+attributeName/i,                        description: 'SVG animate injection' },
  { name: 'xss-base-href-tag',    severity: 'medium',   pattern: /<base[^>]+href/i,                                    description: 'Base href hijack' },
  { name: 'xss-srcset',           severity: 'high',     pattern: /srcset\s*=\s*["']?javascript/i,                      description: 'srcset XSS' },
];

function createXssMiddleware(config) {
  return function xssMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    const sources = [
      { label: 'query',   data: req.query },
      { label: 'body',    data: req.body },
      { label: 'path',    data: req.path },
      { label: 'cookies', data: req.cookies },
    ];

    const hit = scanSources(sources, XSS_RULES);

    if (hit) {
      const ip = req.wafIp || req.socket?.remoteAddress || 'unknown';
      const ruleDef = XSS_RULES.find((r) => r.name === hit.rule);

      logBlock({
        logPath:   config.logPath,
        ip,
        method:    req.method,
        path:      req.path,
        rule:      hit.rule,
        matched:   hit.matched,
        source:    hit.source,
        severity:  ruleDef?.severity || 'medium',
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

module.exports = createXssMiddleware;
