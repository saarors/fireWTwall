'use strict';

const { createDebugMiddleware }                  = require('./debug');
const createSecurityHeadersMiddleware            = require('./securityHeaders');
const createDdosMiddleware                       = require('./ddos');
const createRequestRhythmMiddleware              = require('./requestRhythm');
const createRequestSizeMiddleware                = require('./requestSize');
const createMethodFilterMiddleware               = require('./methodFilter');
const createIpFilterMiddleware                   = require('./ipFilter');
const { createRateLimitMiddleware }              = require('./rateLimit');
const createBotFilterMiddleware                  = require('./botFilter');
const createEntropyScannerMiddleware             = require('./entropyScanner');
const createSemanticTypeCheckMiddleware          = require('./semanticTypeCheck');
const createPrototypePollutionMiddleware         = require('./prototypePollution');
const createSsrfMiddleware                       = require('./ssrf');
const createXxeMiddleware                        = require('./xxe');
const createOpenRedirectMiddleware               = require('./openRedirect');
const createHeaderInjectionMiddleware            = require('./headerInjection');
const createPathTraversalMiddleware              = require('./pathTraversal');
const createCommandInjectionMiddleware           = require('./commandInjection');
const createSqlInjectionMiddleware               = require('./sqlInjection');
const createXssMiddleware                        = require('./xss');
const createSstiMiddleware                       = require('./ssti');
const createRfiMiddleware                        = require('./rfi');
const createLog4shellMiddleware                  = require('./log4shell');
const createShellshockMiddleware                 = require('./shellshock');
const createNosqlInjectionMiddleware             = require('./nosqlInjection');
const createLdapInjectionMiddleware              = require('./ldapInjection');
const createDeserializationMiddleware            = require('./deserialization');
const createHeuristicEngineMiddleware            = require('./heuristicEngine');
const createMutationTrackerMiddleware            = require('./mutationTracker');
const createMultiVectorCorrelationMiddleware     = require('./multiVectorCorrelation');

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
    createRequestRhythmMiddleware(config),         //  3. Timing analysis — bot/scanner detection (early, pre-parse)
    createRequestSizeMiddleware(config),           //  4. Reject oversized payloads early
    createMethodFilterMiddleware(config),          //  5. Kill invalid HTTP methods
    createIpFilterMiddleware(config),              //  6. Whitelist bypass / blacklist block
    createRateLimitMiddleware(config),             //  7. Rate limit (after whitelist check)
    createBotFilterMiddleware(config),             //  8. Block known scanners / bad bots
    createEntropyScannerMiddleware(config),        //  9. Shannon entropy — encoded/obfuscated/binary payloads
    createSemanticTypeCheckMiddleware(config),     // 10. Type confusion — injection in typed params
    createPrototypePollutionMiddleware(config),    // 11. Prototype pollution
    createSsrfMiddleware(config),                  // 12. Server-Side Request Forgery
    createXxeMiddleware(config),                   // 13. XML External Entity injection
    createOpenRedirectMiddleware(config),          // 14. Open redirect
    createHeaderInjectionMiddleware(config),       // 15. CRLF / host-header injection
    createPathTraversalMiddleware(config),         // 16. Path traversal in URL & params
    createCommandInjectionMiddleware(config),      // 17. OS command injection
    createSqlInjectionMiddleware(config),          // 18. SQL injection
    createXssMiddleware(config),                   // 19. XSS
    createSstiMiddleware(config),                  // 20. Server-Side Template Injection
    createRfiMiddleware(config),                   // 21. Remote File Inclusion
    createLog4shellMiddleware(config),             // 22. Log4Shell / JNDI injection
    createShellshockMiddleware(config),            // 23. Shellshock bash injection
    createNosqlInjectionMiddleware(config),        // 24. NoSQL / MongoDB injection
    createLdapInjectionMiddleware(config),         // 25. LDAP injection
    createDeserializationMiddleware(config),       // 26. Unsafe deserialization
    createHeuristicEngineMiddleware(config),       // 27. Zero-day heuristics — structural attack patterns
    createMutationTrackerMiddleware(config),       // 28. Fuzzing detection — payload mutation tracking
    createMultiVectorCorrelationMiddleware(config),// 29. Split-payload correlation — multi-param attacks (last)
  ];
}

module.exports = buildMiddlewareChain;
