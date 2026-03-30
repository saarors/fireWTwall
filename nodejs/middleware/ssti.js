'use strict';

const { scanSources } = require('../utils/patternMatcher');
const { logBlock }    = require('../utils/logger');

// ── Server-Side Template Injection rules ──────────────────────────────────────
// Covers Python (Jinja2/Mako), Twig (PHP), FreeMarker, Velocity, Smarty,
// Ruby ERB, Java EL/Struts2 OGNL, Spring4Shell, and Tornado.
const SSTI_RULES = [
  // ── Python / Jinja2 / Mako ────────────────────────────────────────────────
  { name: 'ssti-python-class',       severity: 'critical', pattern: /\{\{.*__class__.*\}\}/i,                        description: 'Python class introspection via template' },
  { name: 'ssti-python-mro',         severity: 'critical', pattern: /\{\{.*__mro__.*\}\}/i,                          description: 'Python MRO traversal via template' },
  { name: 'ssti-python-subclasses',  severity: 'critical', pattern: /\{\{.*__subclasses__\s*\(\)/i,                  description: 'Python subclass discovery via template' },
  { name: 'ssti-python-popen',       severity: 'critical', pattern: /\{\{.*popen\s*\(|subprocess\s*\./i,             description: 'Python popen/subprocess in template' },
  { name: 'ssti-python-globals',     severity: 'critical', pattern: /\{\{.*__globals__.*\}\}/i,                      description: 'Python globals access via template' },
  { name: 'ssti-python-builtins',    severity: 'critical', pattern: /\{\{.*__builtins__.*\}\}/i,                     description: 'Python builtins access via template' },

  // ── Twig (PHP) ────────────────────────────────────────────────────────────
  { name: 'ssti-twig-self',          severity: 'critical', pattern: /\{\{_self\.env\./i,                             description: 'Twig _self RCE' },
  { name: 'ssti-twig-filter',        severity: 'critical', pattern: /registerUndefinedFilterCallback/i,               description: 'Twig filter callback RCE' },

  // ── FreeMarker (Java) ─────────────────────────────────────────────────────
  { name: 'ssti-freemarker',         severity: 'critical', pattern: /<#assign[^>]*Execute|freemarker\.template\.utility\.Execute/i, description: 'FreeMarker Execute RCE' },

  // ── Apache Velocity ───────────────────────────────────────────────────────
  { name: 'ssti-velocity',           severity: 'critical', pattern: /#set\s*\(\s*\$[a-z]+\s*=\s*["']?\s*\$class|#set.*Runtime/i, description: 'Velocity template RCE' },

  // ── Smarty (PHP) ──────────────────────────────────────────────────────────
  { name: 'ssti-smarty-php',         severity: 'critical', pattern: /\{php\}|\{\/php\}/i,                            description: 'Smarty PHP execution block' },
  { name: 'ssti-smarty-system',      severity: 'critical', pattern: /\{system\s*\(|\{passthru\s*\(/i,                description: 'Smarty system/passthru call' },

  // ── Ruby ERB ─────────────────────────────────────────────────────────────
  { name: 'ssti-erb',                severity: 'critical', pattern: /<%=\s*(system|`|\%x|IO\.popen|exec)/i,          description: 'Ruby ERB code execution' },

  // ── Java EL / Spring ─────────────────────────────────────────────────────
  { name: 'ssti-java-runtime',       severity: 'critical', pattern: /\$\{.*Runtime.*exec|\$\{.*ProcessBuilder/i,     description: 'Java template Runtime/ProcessBuilder' },

  // ── Struts2 / OGNL ────────────────────────────────────────────────────────
  { name: 'ssti-ognl-expression',    severity: 'critical', pattern: /%\{#[a-zA-Z_]|%25\{#|\$\{#context\[/i,         description: 'Struts2/OGNL expression injection' },
  { name: 'ssti-ognl-member',        severity: 'critical', pattern: /#_memberAccess|@java\.lang\.Runtime|new java\.lang\.ProcessBuilder/i, description: 'OGNL member access / Java reflection' },

  // ── Spring4Shell ─────────────────────────────────────────────────────────
  { name: 'ssti-spring-classloader', severity: 'critical', pattern: /class\.module\.classLoader|class\.classLoader\.urls/i, description: 'Spring4Shell classLoader RCE' },

  // ── Tornado (Python) ─────────────────────────────────────────────────────
  { name: 'ssti-tornado-import',     severity: 'critical', pattern: /\{%\s*import\s+os\s*%\}/i,                     description: 'Tornado template OS import' },
];

/**
 * SSTI middleware — scans query params, body, URL path, and cookies for
 * server-side template injection payloads.
 *
 * @param {object} config - WAF configuration
 * @returns {Function} Express middleware
 */
function createSstiMiddleware(config) {
  return function sstiMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    const sources = [
      { label: 'query',   data: req.query },
      { label: 'body',    data: req.body },
      { label: 'path',    data: req.path },
      { label: 'cookies', data: req.cookies },
    ];

    const hit = scanSources(sources, SSTI_RULES);

    if (hit) {
      const ip      = req.wafIp || req.socket?.remoteAddress || 'unknown';
      const ruleDef = SSTI_RULES.find((r) => r.name === hit.rule);

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

module.exports = createSstiMiddleware;
