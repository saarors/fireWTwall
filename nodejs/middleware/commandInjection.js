'use strict';

const { scanSources } = require('../utils/patternMatcher');
const { logBlock } = require('../utils/logger');

const CMD_RULES = [
  // ── Shell command separators ───────────────────────────────────────────
  { name: 'cmd-pipe',           severity: 'critical', pattern: /[|;`]\s*(?:ls|cat|whoami|id|uname|wget|curl|bash|sh|python|perl|ruby|nc|netcat|ncat)\b/i },
  { name: 'cmd-subshell',       severity: 'critical', pattern: /\$\([^)]*\)|\`[^`]*\`/ },
  { name: 'cmd-redirection',    severity: 'high',     pattern: /(?:^|[^<])>{1,2}\s*\/(?:etc|tmp|var|dev)/ },
  { name: 'cmd-path-exec',      severity: 'critical', pattern: /\/(?:bin|usr\/bin|usr\/local\/bin)\/\w+/ },

  // ── Windows-specific ───────────────────────────────────────────────────
  { name: 'cmd-win-shell',      severity: 'critical', pattern: /(?:cmd\.exe|powershell(?:\.exe)?|wscript|cscript)\b/i },
  { name: 'cmd-win-net',        severity: 'high',     pattern: /\bnet\s+(?:user|group|localgroup|share)\b/i },
  { name: 'cmd-win-reg',        severity: 'high',     pattern: /\breg(?:\.exe)?\s+(?:add|delete|query|export)/i },

  // ── Common SSRF / RCE gadgets ──────────────────────────────────────────
  { name: 'cmd-wget-curl',      severity: 'critical', pattern: /\b(?:wget|curl)\s+(?:https?|ftp):\/\//i },
  { name: 'cmd-eval',           severity: 'critical', pattern: /\beval\s*\(/ },
  { name: 'cmd-base64-decode',  severity: 'high',     pattern: /base64\s*(?:--decode|-d)\b/i },

  // ── New rules (v2) — interpreter one-liners & enumeration ─────────────
  { name: 'cmd-python-exec',    severity: 'critical', pattern: /python[23]?\s+-[cC]\s+["']?.*import|python[23]?\s+-[cC]\s+["']?.*exec/i, description: 'Python code execution' },
  { name: 'cmd-ruby-exec',      severity: 'critical', pattern: /ruby\s+-e\s+["']?/i,                                                      description: 'Ruby code execution' },
  { name: 'cmd-perl-exec',      severity: 'critical', pattern: /perl\s+-e\s+["']?/i,                                                      description: 'Perl code execution' },
  { name: 'cmd-php-exec',       severity: 'critical', pattern: /php\s+-r\s+["']?/i,                                                       description: 'PHP CLI code execution' },
  { name: 'cmd-node-exec',      severity: 'critical', pattern: /node\s+-e\s+["']?/i,                                                      description: 'Node.js code execution' },
  { name: 'cmd-netcat',         severity: 'critical', pattern: /\bnc\s+-[enlvz]|\bnetcat\b/i,                                             description: 'Netcat reverse shell' },
  { name: 'cmd-whoami',         severity: 'high',     pattern: /\bwhoami\b|\bid\b|\bpasswd\b/i,                                           description: 'System enumeration commands' },
  { name: 'cmd-env-dump',       severity: 'high',     pattern: /\bprintenv\b|\benv\b\s*$|\bset\b\s*$|\bexport\b\s*$/im,                   description: 'Environment variable dump' },
];

function createCommandInjectionMiddleware(config) {
  return function commandInjectionMiddleware(req, res, next) {
    if (req.wafTrusted) return next();

    const sources = [
      { label: 'query',   data: req.query },
      { label: 'body',    data: req.body },
      { label: 'path',    data: req.path },
      { label: 'cookies', data: req.cookies },
    ];

    const hit = scanSources(sources, CMD_RULES);

    if (hit) {
      const ip = req.wafIp || req.socket?.remoteAddress || 'unknown';
      const ruleDef = CMD_RULES.find((r) => r.name === hit.rule);

      logBlock({
        logPath:   config.logPath,
        ip,
        method:    req.method,
        path:      req.path,
        rule:      hit.rule,
        matched:   hit.matched,
        source:    hit.source,
        severity:  ruleDef?.severity || 'high',
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

module.exports = createCommandInjectionMiddleware;
