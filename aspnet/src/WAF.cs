using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Web;
using FireWTWall.Detectors;

namespace FireWTWall
{
    /// <summary>
    /// Core WAF orchestrator.
    ///
    /// Runs the check pipeline in order and either blocks or passes each request.
    /// Security headers are always added on clean pass.
    /// Equivalent to php/src/WAF.php and the nodejs middleware chain.
    /// </summary>
    public sealed class WAF
    {
        private readonly WafConfig   _config;
        private readonly WafLogger   _logger;
        private readonly IpFilter    _ipFilter;
        private readonly RateLimiter _rateLimiter;
        private readonly BotDetector _botDetector;

        private readonly string  _requestId;
        private readonly Stopwatch _sw;

        public WAF(WafConfig config, BotConfig botConfig)
        {
            _config      = config;
            _logger      = new WafLogger(config.LogPath);
            _ipFilter    = new IpFilter(config.Whitelist, config.Blacklist);
            _rateLimiter = new RateLimiter(config.RateLimit);
            _botDetector = new BotDetector(botConfig);
            _requestId   = Guid.NewGuid().ToString("N").Substring(0, 16);
            _sw          = Stopwatch.StartNew();
        }

        /// <summary>
        /// Execute the WAF pipeline.
        /// Returns normally if the request is clean (security headers are still added).
        /// Calls WafResponse.Block() (which calls Response.End()) if the request must be blocked.
        /// </summary>
        public void Run(HttpContext ctx)
        {
            var req = new WafRequest(ctx, _config.TrustedProxies);
            string ip   = req.Ip;
            string path = req.Path;

            // --- 0. DDoS protection (runs before bypass-path check) ---
            DdosProtection.Run(req, _config, _logger);

            // --- Bypass paths ---
            foreach (string bypassPath in _config.BypassPaths)
            {
                if (path.StartsWith(bypassPath, StringComparison.OrdinalIgnoreCase))
                {
                    WafResponse.SendSecurityHeaders(ctx);
                    return;
                }
            }

            // --- 1. Request size ---
            if (req.ContentLength > 0 && req.ContentLength > _config.MaxBodySize)
                Block(ctx, req, "request-size", ip, "header", "", "medium", 413);

            // --- 2. HTTP method ---
            string method = req.Method;
            bool methodAllowed = false;
            foreach (string m in _config.AllowedMethods)
                if (method == m) { methodAllowed = true; break; }

            if (!methodAllowed)
            {
                _logger.LogBlock(ip, method, path, "method-not-allowed", "", "", "medium", req.UserAgent);
                if (_config.Mode != "log-only")
                    WafResponse.MethodNotAllowed(ctx, _config.AllowedMethods);
            }

            // --- 3. IP filter ---
            string ipResult = _ipFilter.Check(ip);
            if (ipResult == "blacklist")
                Block(ctx, req, "ip-blacklist", ip, "", "", "high");

            bool trusted = (ipResult == "whitelist");
            if (trusted)
            {
                WafResponse.SendSecurityHeaders(ctx);
                return;
            }

            // --- 4. Rate limit ---
            var rl = _rateLimiter.Check(ip);
            if (!rl.Allowed)
            {
                _logger.LogBlock(ip, method, path, "rate-limit", "", "", "medium", req.UserAgent);
                if (_config.Mode != "log-only")
                    WafResponse.TooManyRequests(ctx, rl.RetryAfter, _config.ResponseType);
            }
            else
            {
                ctx.Response.AddHeader("X-RateLimit-Limit",     _config.RateLimit.MaxRequests.ToString());
                ctx.Response.AddHeader("X-RateLimit-Remaining", rl.Remaining.ToString());
            }

            // --- 5. Bot detection ---
            var botHit = _botDetector.Check(req.UserAgent);
            if (botHit != null)
                Block(ctx, req, botHit.Rule, ip, "user-agent", botHit.Matched, botHit.Severity);

            // --- 5a. SSRF ---
            var hit = SsrfDetector.Scan(req);
            if (hit != null) Block(ctx, req, hit.Rule, ip, hit.Source, hit.Matched, hit.Severity);

            // --- 5b. XXE ---
            hit = XxeDetector.Scan(req);
            if (hit != null) Block(ctx, req, hit.Rule, ip, hit.Source, hit.Matched, hit.Severity);

            // --- 5c. Open redirect ---
            hit = OpenRedirectDetector.Scan(req);
            if (hit != null) Block(ctx, req, hit.Rule, ip, hit.Source, hit.Matched, hit.Severity);

            // --- 5d. Mass assignment ---
            hit = MassAssignmentDetector.Scan(req);
            if (hit != null) Block(ctx, req, hit.Rule, ip, hit.Source, hit.Matched, hit.Severity);

            // --- 6. Header injection (CRLF + host injection) ---
            string host = "";
            req.Headers.TryGetValue("host", out host);
            hit = HeaderInjectionDetector.Scan(req.Headers, host ?? "");
            if (hit != null) Block(ctx, req, hit.Rule, ip, hit.Source, hit.Matched, hit.Severity);

            // Collect decoded sources for pattern detectors
            var sources = new Dictionary<string, string>
            {
                ["query"]   = FlattenDict(req.Query),
                ["body"]    = FlattenDict(req.Form),
                ["path"]    = path,
                ["cookies"] = FlattenDict(req.Cookies),
            };

            // --- 7. Path traversal ---
            hit = PathTraversalDetector.Scan(sources);
            if (hit != null) Block(ctx, req, hit.Rule, ip, hit.Source, hit.Matched, hit.Severity);

            // --- 8. Command injection ---
            hit = CommandInjectionDetector.Scan(sources);
            if (hit != null) Block(ctx, req, hit.Rule, ip, hit.Source, hit.Matched, hit.Severity);

            // --- 9. SQL injection ---
            hit = SqlInjectionDetector.Scan(sources);
            if (hit != null) Block(ctx, req, hit.Rule, ip, hit.Source, hit.Matched, hit.Severity);

            // --- 10. XSS ---
            hit = XssDetector.Scan(sources);
            if (hit != null) Block(ctx, req, hit.Rule, ip, hit.Source, hit.Matched, hit.Severity);

            // --- 11. SSTI ---
            hit = SstiDetector.Scan(sources);
            if (hit != null) Block(ctx, req, hit.Rule, ip, hit.Source, hit.Matched, hit.Severity);

            // --- 12. RFI ---
            hit = RfiDetector.Scan(req);
            if (hit != null) Block(ctx, req, hit.Rule, ip, hit.Source, hit.Matched, hit.Severity);

            // --- 13. Log4Shell ---
            hit = Log4ShellDetector.Scan(req);
            if (hit != null) Block(ctx, req, hit.Rule, ip, hit.Source, hit.Matched, hit.Severity);

            // --- 14. Shellshock ---
            hit = ShellshockDetector.Scan(req);
            if (hit != null) Block(ctx, req, hit.Rule, ip, hit.Source, hit.Matched, hit.Severity);

            // --- 15. NoSQL injection ---
            hit = NoSqlInjectionDetector.Scan(req);
            if (hit != null) Block(ctx, req, hit.Rule, ip, hit.Source, hit.Matched, hit.Severity);

            // --- 16. LDAP injection ---
            hit = LdapInjectionDetector.Scan(req);
            if (hit != null) Block(ctx, req, hit.Rule, ip, hit.Source, hit.Matched, hit.Severity);

            // --- 17. Deserialization ---
            hit = DeserializationDetector.Scan(req);
            if (hit != null) Block(ctx, req, hit.Rule, ip, hit.Source, hit.Matched, hit.Severity);

            // All checks passed
            WafResponse.SendSecurityHeaders(ctx);

            if (_config.Debug)
            {
                double durationMs = Math.Round(_sw.Elapsed.TotalMilliseconds, 3);
                ctx.Response.AddHeader("X-WAF-RequestId", _requestId);
                ctx.Response.AddHeader("X-WAF-Result",    "passed");
                ctx.Response.AddHeader("X-WAF-Time",      durationMs + "ms");

                _logger.LogPass(ip, method, path, req.UserAgent, _requestId, durationMs);
            }
        }

        // ------------------------------------------------------------------ //
        // Internal helpers
        // ------------------------------------------------------------------ //

        private void Block(HttpContext ctx, WafRequest req,
                           string rule, string ip, string source, string matched,
                           string severity = "medium", int status = 403)
        {
            double durationMs = Math.Round(_sw.Elapsed.TotalMilliseconds, 3);

            _logger.LogBlock(ip, req.Method, req.Path,
                             rule, matched, source, severity, req.UserAgent,
                             _requestId, durationMs);

            if (_config.Debug)
            {
                ctx.Response.AddHeader("X-WAF-RequestId", _requestId);
                ctx.Response.AddHeader("X-WAF-Result",    "blocked");
                ctx.Response.AddHeader("X-WAF-Rule",      rule);
                ctx.Response.AddHeader("X-WAF-Time",      durationMs + "ms");
            }

            if (_config.Mode == "log-only") return;

            WafResponse.Block(ctx, rule, status, _config.ResponseType);
            // WafResponse.Block() calls Response.End() — execution stops here in reject mode.
        }

        /// <summary>
        /// Flatten a Dictionary to a single newline-separated string for pattern scanning.
        /// Detectors that need individual keys (SSRF, RFI, etc.) use the WafRequest directly.
        /// </summary>
        private static string FlattenDict(Dictionary<string, string> dict)
        {
            if (dict == null || dict.Count == 0) return "";
            return string.Join("\n", dict.Values);
        }
    }
}
