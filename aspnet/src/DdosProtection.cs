using System;
using System.Runtime.Caching;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace FireWTWall
{
    /// <summary>
    /// Layer-7 DDoS protection.
    /// Uses MemoryCache for shared state across IIS worker threads.
    /// Equivalent to php/src/DdosProtection.php and nodejs/middleware/ddos.js.
    /// </summary>
    public static class DdosProtection
    {
        private static readonly MemoryCache _cache = new MemoryCache("waf_ddos");
        private static readonly object      _sync  = new object();

        // Per-process fallback counters (used only if MemoryCache is somehow unavailable)
        private static long _globalCount       = 0;
        private static long _globalWindowStart = 0;

        public static void Run(WafRequest request, WafConfig config, WafLogger logger)
        {
            var ddos = config.Ddos;
            string ip   = request.Ip;
            string path = request.Path;
            string ua   = request.UserAgent;

            // ------------------------------------------------------------------
            // Layer 1 — URL length guard
            // ------------------------------------------------------------------
            string uri = HttpContext.Current?.Request?.RawUrl ?? path;
            if (uri.Length > ddos.MaxUrlLength)
                Block(request, config, logger, "ddos-url-length", 414, "URI Too Long");

            // ------------------------------------------------------------------
            // Layer 2 — Header count guard
            // ------------------------------------------------------------------
            int headerCount = HttpContext.Current?.Request?.Headers?.Count ?? 0;
            if (headerCount > ddos.MaxHeaderCount)
                Block(request, config, logger, "ddos-header-count", 431, "Too many request headers");

            // ------------------------------------------------------------------
            // Layer 3 — Header size guard
            // ------------------------------------------------------------------
            foreach (string hKey in HttpContext.Current?.Request?.Headers ?? new System.Collections.Specialized.NameValueCollection())
            {
                string hVal = HttpContext.Current.Request.Headers[hKey] ?? "";
                if (hVal.Length > ddos.MaxHeaderSize)
                    Block(request, config, logger, "ddos-header-size", 431, "Request header field too large");
            }

            // ------------------------------------------------------------------
            // Layer 4 — Burst rate limiter (per-IP, short window)
            // ------------------------------------------------------------------
            {
                string burstKey = "burst_" + Md5(ip);
                string blockKey = "burst_bl_" + Md5(ip);
                string bcKey    = "burst_bc_" + Md5(ip);

                lock (_sync)
                {
                    if (_cache.Contains(blockKey))
                    {
                        int blockCount = (int)(_cache.Get(bcKey) ?? 0);
                        if (ddos.Tarpit.Enabled && blockCount > 3)
                            System.Threading.Thread.Sleep(ddos.Tarpit.DelayMs);
                        Block(request, config, logger, "ddos-burst", 429, "Burst rate limit exceeded");
                    }

                    var entry = (long[])_cache.Get(burstKey); // [windowStart (unix ms), count]
                    long now  = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                    if (entry == null || (now - entry[0]) >= ddos.Burst.WindowSec * 1000L)
                        entry = new long[] { now, 0 };

                    entry[1]++;
                    _cache.Set(burstKey, entry, new CacheItemPolicy
                    {
                        AbsoluteExpiration = DateTimeOffset.UtcNow.AddSeconds(ddos.Burst.WindowSec * 2)
                    });

                    if (entry[1] > ddos.Burst.MaxRequests)
                    {
                        _cache.Set(blockKey, true, new CacheItemPolicy
                        {
                            AbsoluteExpiration = DateTimeOffset.UtcNow.AddSeconds(ddos.Burst.BlockDurationSec)
                        });
                        int bc = (int)(_cache.Get(bcKey) ?? 0) + 1;
                        _cache.Set(bcKey, bc, new CacheItemPolicy
                        {
                            AbsoluteExpiration = DateTimeOffset.UtcNow.AddSeconds(ddos.Burst.BlockDurationSec + 60)
                        });
                        Block(request, config, logger, "ddos-burst", 429, "Burst rate limit exceeded");
                    }
                }
            }

            // ------------------------------------------------------------------
            // Layer 5 — Global rate limiter (all IPs combined)
            // ------------------------------------------------------------------
            {
                lock (_sync)
                {
                    long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    var  g   = (long[])_cache.Get("global_counter"); // [windowStart, count]

                    if (g == null || (now - g[0]) >= ddos.Global.WindowSec * 1000L)
                        g = new long[] { now, 0 };

                    g[1]++;
                    _cache.Set("global_counter", g, new CacheItemPolicy
                    {
                        AbsoluteExpiration = DateTimeOffset.UtcNow.AddSeconds(ddos.Global.WindowSec * 2)
                    });

                    if (g[1] > ddos.Global.MaxRequests)
                        Block(request, config, logger, "ddos-global-flood", 503, "Service temporarily unavailable");
                }
            }

            // ------------------------------------------------------------------
            // Layer 6 — Request fingerprint flood detection
            // ------------------------------------------------------------------
            {
                string fpRaw  = ip + "\x00" + ua + "\x00" + path;
                string fpHash = Md5(fpRaw);
                string fpKey  = "fp_" + fpHash;
                string fpBlk  = "fp_bl_" + fpHash;

                lock (_sync)
                {
                    if (_cache.Contains(fpBlk))
                        Block(request, config, logger, "ddos-fingerprint-flood", 429, "Request fingerprint flood detected");

                    var entry = (long[])_cache.Get(fpKey);
                    long now  = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                    if (entry == null || (now - entry[0]) >= ddos.Fingerprint.WindowSec * 1000L)
                        entry = new long[] { now, 0 };

                    entry[1]++;
                    _cache.Set(fpKey, entry, new CacheItemPolicy
                    {
                        AbsoluteExpiration = DateTimeOffset.UtcNow.AddSeconds(ddos.Fingerprint.WindowSec * 2)
                    });

                    if (entry[1] > ddos.Fingerprint.MaxRequests)
                    {
                        _cache.Set(fpBlk, true, new CacheItemPolicy
                        {
                            AbsoluteExpiration = DateTimeOffset.UtcNow.AddSeconds(ddos.Fingerprint.BlockDurationSec)
                        });
                        Block(request, config, logger, "ddos-fingerprint-flood", 429, "Request fingerprint flood detected");
                    }
                }
            }

            // ------------------------------------------------------------------
            // Layer 7 — Repeated path flood (cross-IP, same endpoint)
            // ------------------------------------------------------------------
            {
                string pathKey = "path_" + Md5(path);

                lock (_sync)
                {
                    var entry = (long[])_cache.Get(pathKey);
                    long now  = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                    if (entry == null || (now - entry[0]) >= ddos.PathFlood.WindowSec * 1000L)
                        entry = new long[] { now, 0 };

                    entry[1]++;
                    _cache.Set(pathKey, entry, new CacheItemPolicy
                    {
                        AbsoluteExpiration = DateTimeOffset.UtcNow.AddSeconds(ddos.PathFlood.WindowSec * 2)
                    });

                    if (entry[1] > ddos.PathFlood.MaxRequests)
                        Block(request, config, logger, "ddos-path-flood", 503, "Service temporarily unavailable");
                }
            }
        }

        // ------------------------------------------------------------------ //
        // Internal helpers
        // ------------------------------------------------------------------ //

        private static void Block(WafRequest request, WafConfig config, WafLogger logger,
                                   string rule, int httpCode, string msg)
        {
            string severity = (rule.StartsWith("ddos-global") || rule.StartsWith("ddos-path"))
                ? "critical" : "high";

            logger.LogBlock(request.Ip, request.Method, request.Path,
                            rule, "", "ddos", severity, request.UserAgent);

            if (config.Mode == "log-only") return;

            var ctx = HttpContext.Current;
            if (httpCode == 429) ctx.Response.AddHeader("Retry-After", "60");
            if (httpCode == 503) ctx.Response.AddHeader("Retry-After", "5");

            WafResponse.Block(ctx, rule, httpCode, config.ResponseType);
        }

        private static string Md5(string input)
        {
            using (var md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(input));
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }
    }
}
