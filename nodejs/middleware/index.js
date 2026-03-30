'use strict';

const { createDebugMiddleware }             = require('./debug');
const createSecurityHeadersMiddleware       = require('./securityHeaders');
const createRequestSizeMiddleware           = require('./requestSize');
const createMethodFilterMiddleware          = require('./methodFilter');
const createIpFilterMiddleware              = require('./ipFilter');
const { createRateLimitMiddleware }         = require('./rateLimit');
const createBotFilterMiddleware             = require('./botFilter');
const createPrototypePollutionMiddleware    = require('./prototypePollution');
const createSsrfMiddleware                  = require('./ssrf');
const createXxeMiddleware                   = require('./xxe');
const createOpenRedirectMiddleware          = require('./openRedirect');
const createHeaderInjectionMiddleware       = require('./headerInjection');
const createPathTraversalMiddleware         = require('./pathTraversal');
const createCommandInjectionMiddleware      = require('./commandInjection');
const createSqlInjectionMiddleware          = require('./sqlInjection');
const createXssMiddleware                   = require('./xss');

/**
 * Returns an ordered array of Express middleware for the WAF.
 *
 * @param {object} config - Merged WAF configuration
 * @returns {Function[]}
 */
function buildMiddlewareChain(config) {
  return [
    createDebugMiddleware(config),                //  0. Request ID + timing (debug mode)
    createSecurityHeadersMiddleware(),             //  1. Defensive response headers
    createRequestSizeMiddleware(config),           //  2. Reject oversized payloads early
    createMethodFilterMiddleware(config),          //  3. Kill invalid HTTP methods
    createIpFilterMiddleware(config),              //  4. Whitelist bypass / blacklist block
    createRateLimitMiddleware(config),             //  5. Rate limit (after whitelist check)
    createBotFilterMiddleware(config),             //  6. Block known scanners / bad bots
    createPrototypePollutionMiddleware(config),    //  7. Prototype pollution
    createSsrfMiddleware(config),                  //  8. Server-Side Request Forgery
    createXxeMiddleware(config),                   //  9. XML External Entity injection
    createOpenRedirectMiddleware(config),          // 10. Open redirect
    createHeaderInjectionMiddleware(config),       // 11. CRLF / host-header injection
    createPathTraversalMiddleware(config),         // 12. Path traversal in URL & params
    createCommandInjectionMiddleware(config),      // 13. OS command injection
    createSqlInjectionMiddleware(config),          // 14. SQL injection
    createXssMiddleware(config),                   // 15. XSS
  ];
}

module.exports = buildMiddlewareChain;
