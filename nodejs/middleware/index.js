'use strict';

const createSecurityHeadersMiddleware  = require('./securityHeaders');
const createRequestSizeMiddleware      = require('./requestSize');
const createMethodFilterMiddleware     = require('./methodFilter');
const createIpFilterMiddleware         = require('./ipFilter');
const { createRateLimitMiddleware }    = require('./rateLimit');
const createBotFilterMiddleware        = require('./botFilter');
const createHeaderInjectionMiddleware  = require('./headerInjection');
const createPathTraversalMiddleware    = require('./pathTraversal');
const createCommandInjectionMiddleware = require('./commandInjection');
const createSqlInjectionMiddleware     = require('./sqlInjection');
const createXssMiddleware              = require('./xss');

/**
 * Returns an ordered array of Express middleware for the WAF.
 * Order matters: cheapest / most definitive checks run first to avoid
 * expensive regex work on requests that would be blocked anyway.
 *
 * @param {object} config - Merged WAF configuration
 * @returns {Function[]}
 */
function buildMiddlewareChain(config) {
  return [
    createSecurityHeadersMiddleware(),        //  0. Set defensive response headers
    createRequestSizeMiddleware(config),      //  1. Reject oversized payloads early
    createMethodFilterMiddleware(config),     //  2. Kill invalid HTTP methods
    createIpFilterMiddleware(config),         //  3. Whitelist bypass / blacklist block
    createRateLimitMiddleware(config),        //  4. Rate limit (after whitelist check)
    createBotFilterMiddleware(config),        //  5. Block known scanners / bad bots
    createHeaderInjectionMiddleware(config),  //  6. CRLF / host-header injection
    createPathTraversalMiddleware(config),    //  7. Path traversal in URL & params
    createCommandInjectionMiddleware(config), //  8. OS command injection
    createSqlInjectionMiddleware(config),     //  9. SQL injection
    createXssMiddleware(config),              // 10. XSS
  ];
}

module.exports = buildMiddlewareChain;
