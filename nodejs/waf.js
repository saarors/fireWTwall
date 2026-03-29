'use strict';

const path = require('path');
const defaultConfig = require('./config/waf.config');
const buildMiddlewareChain = require('./middleware/index');

/**
 * Creates a WAF middleware stack for Express.
 *
 * @param {Partial<typeof defaultConfig>} [options]
 * @returns {Function[]} Array of Express middleware — spread into app.use()
 *
 * @example
 * const { createWAF } = require('./waf');
 * app.use(...createWAF({ mode: 'reject', rateLimit: { maxRequests: 200 } }));
 */
function createWAF(options = {}) {
  const config = mergeConfig(defaultConfig, options);
  return buildMiddlewareChain(config);
}

/**
 * Deep-merge user options into the default config.
 * Only keys present in the default config are accepted.
 */
function mergeConfig(defaults, overrides) {
  const merged = { ...defaults };

  for (const key of Object.keys(overrides)) {
    if (!(key in defaults)) continue; // Ignore unknown keys

    const base = defaults[key];
    const override = overrides[key];

    if (
      typeof base === 'object' &&
      base !== null &&
      !Array.isArray(base) &&
      typeof override === 'object' &&
      override !== null &&
      !Array.isArray(override)
    ) {
      merged[key] = { ...base, ...override };
    } else {
      merged[key] = override;
    }
  }

  // Resolve logPath relative to the caller's CWD
  if (!path.isAbsolute(merged.logPath)) {
    merged.logPath = path.resolve(process.cwd(), merged.logPath);
  }

  return merged;
}

module.exports = { createWAF };
