'use strict';

/**
 * Adds defensive HTTP security headers to every response and removes
 * headers that leak server implementation details.
 *
 * All headers are set once, before any route handler runs, by attaching
 * them directly inside the middleware (not via a res.on('finish') hook)
 * so they are present even on early 4xx/5xx responses.
 */
function createSecurityHeadersMiddleware() {
  const headers = {
    // ── Classic hardening ──────────────────────────────────────────────────
    'X-Content-Type-Options':           'nosniff',
    'X-Frame-Options':                  'SAMEORIGIN',
    'X-XSS-Protection':                 '1; mode=block',
    'Referrer-Policy':                  'strict-origin-when-cross-origin',

    // Extended Permissions-Policy (payment and usb added)
    'Permissions-Policy':               'geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()',

    // ── Cross-origin isolation ─────────────────────────────────────────────
    'Cross-Origin-Opener-Policy':       'same-origin',
    'Cross-Origin-Resource-Policy':     'same-origin',
    'Cross-Origin-Embedder-Policy':     'require-corp',

    // ── Transport security ─────────────────────────────────────────────────
    'Strict-Transport-Security':        'max-age=31536000; includeSubDomains; preload',

    // ── Content Security Policy ────────────────────────────────────────────
    'Content-Security-Policy':          "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",

    // ── Miscellaneous ──────────────────────────────────────────────────────
    'X-Permitted-Cross-Domain-Policies': 'none',

    // Network Error Logging — instructs browsers to report network failures
    'NEL': '{"report_to":"default","max_age":31536000,"include_subdomains":true}',
  };

  return function securityHeadersMiddleware(_req, res, next) {
    // Remove header that leaks the server technology stack
    res.removeHeader('X-Powered-By');

    for (const [name, value] of Object.entries(headers)) {
      res.set(name, value);
    }

    next();
  };
}

module.exports = createSecurityHeadersMiddleware;
