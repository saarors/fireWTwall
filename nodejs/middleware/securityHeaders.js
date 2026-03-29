'use strict';

/**
 * Adds defensive HTTP security headers to every response.
 * This runs as a response interceptor by wrapping res.setHeader.
 */
function createSecurityHeadersMiddleware() {
  const headers = {
    'X-Content-Type-Options':           'nosniff',
    'X-Frame-Options':                  'SAMEORIGIN',
    'X-XSS-Protection':                 '1; mode=block',
    'Referrer-Policy':                  'strict-origin-when-cross-origin',
    'Permissions-Policy':               'geolocation=(), microphone=(), camera=()',
    'X-DNS-Prefetch-Control':           'off',
    'Cross-Origin-Opener-Policy':       'same-origin',
    'Cross-Origin-Resource-Policy':     'same-origin',
  };

  return function securityHeadersMiddleware(_req, res, next) {
    for (const [name, value] of Object.entries(headers)) {
      res.set(name, value);
    }
    next();
  };
}

module.exports = createSecurityHeadersMiddleware;
