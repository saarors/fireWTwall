'use strict';

const { createDebugMiddleware }             = require('./debug');
const createSecurityHeadersMiddleware       = require('./securityHeaders');
const createDdosMiddleware                  = require('./ddos');
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
const createSstiMiddleware                  = require('./ssti');
const createRfiMiddleware                   = require('./rfi');
const createLog4shellMiddleware             = require('./log4shell');
const createShellshockMiddleware            = require('./shellshock');
const createNosqlInjectionMiddleware        = require('./nosqlInjection');
const createLdapInjectionMiddleware         = require('./ldapInjection');
const createDeserializationMiddleware       = require('./deserialization');

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
    createDdosMiddleware(config),                  //  2. DDoS protection (burst/flood/fingerprint)
    createRequestSizeMiddleware(config),           //  3. Reject oversized payloads early
    createMethodFilterMiddleware(config),          //  4. Kill invalid HTTP methods
    createIpFilterMiddleware(config),              //  5. Whitelist bypass / blacklist block
    createRateLimitMiddleware(config),             //  6. Rate limit (after whitelist check)
    createBotFilterMiddleware(config),             //  7. Block known scanners / bad bots
    createPrototypePollutionMiddleware(config),    //  8. Prototype pollution
    createSsrfMiddleware(config),                  //  9. Server-Side Request Forgery
    createXxeMiddleware(config),                   // 10. XML External Entity injection
    createOpenRedirectMiddleware(config),          // 11. Open redirect
    createHeaderInjectionMiddleware(config),       // 12. CRLF / host-header injection
    createPathTraversalMiddleware(config),         // 13. Path traversal in URL & params
    createCommandInjectionMiddleware(config),      // 14. OS command injection
    createSqlInjectionMiddleware(config),          // 15. SQL injection
    createXssMiddleware(config),                   // 16. XSS
    createSstiMiddleware(config),                  // 17. Server-Side Template Injection
    createRfiMiddleware(config),                   // 18. Remote File Inclusion
    createLog4shellMiddleware(config),             // 19. Log4Shell / JNDI injection
    createShellshockMiddleware(config),            // 20. Shellshock bash injection
    createNosqlInjectionMiddleware(config),        // 21. NoSQL / MongoDB injection
    createLdapInjectionMiddleware(config),         // 22. LDAP injection
    createDeserializationMiddleware(config),       // 23. Unsafe deserialization
  ];
}

module.exports = buildMiddlewareChain;
