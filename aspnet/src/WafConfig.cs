using System;
using System.IO;

namespace FireWTWall
{
    public sealed class DdosBurstConfig
    {
        public int WindowSec        { get; set; } = 1;
        public int MaxRequests      { get; set; } = 20;
        public int BlockDurationSec { get; set; } = 60;
    }

    public sealed class DdosGlobalConfig
    {
        public int WindowSec   { get; set; } = 1;
        public int MaxRequests { get; set; } = 500;
    }

    public sealed class DdosFingerprintConfig
    {
        public int WindowSec        { get; set; } = 10;
        public int MaxRequests      { get; set; } = 50;
        public int BlockDurationSec { get; set; } = 60;
    }

    public sealed class DdosPathFloodConfig
    {
        public int WindowSec   { get; set; } = 5;
        public int MaxRequests { get; set; } = 200;
    }

    public sealed class DdosTarpitConfig
    {
        public bool Enabled { get; set; } = false;
        public int  DelayMs { get; set; } = 2000;
    }

    public sealed class DdosConfig
    {
        public int                   MaxUrlLength   { get; set; } = 2048;
        public int                   MaxHeaderCount { get; set; } = 100;
        public int                   MaxHeaderSize  { get; set; } = 8192;
        public DdosBurstConfig       Burst          { get; set; } = new DdosBurstConfig();
        public DdosGlobalConfig      Global         { get; set; } = new DdosGlobalConfig();
        public DdosFingerprintConfig Fingerprint    { get; set; } = new DdosFingerprintConfig();
        public DdosPathFloodConfig   PathFlood      { get; set; } = new DdosPathFloodConfig();
        public DdosTarpitConfig      Tarpit         { get; set; } = new DdosTarpitConfig();
    }

    public sealed class RateLimitConfig
    {
        public int WindowSec        { get; set; } = 60;
        public int MaxRequests      { get; set; } = 100;
        public int BlockDurationSec { get; set; } = 600;
    }

    /// <summary>
    /// Centralised WAF configuration.
    ///
    /// Usage — override defaults in Global.asax Application_Start:
    ///   WafConfig.Current.Mode = "log-only";
    ///   WafConfig.Current.RateLimit.MaxRequests = 200;
    /// </summary>
    public sealed class WafConfig
    {
        // ------------------------------------------------------------------ //
        // Singleton
        // ------------------------------------------------------------------ //

        private static WafConfig _current;
        private static readonly object _lock = new object();

        public static WafConfig Current
        {
            get
            {
                if (_current != null) return _current;
                lock (_lock)
                {
                    if (_current == null) _current = new WafConfig();
                }
                return _current;
            }
        }

        // ------------------------------------------------------------------ //
        // Settings
        // ------------------------------------------------------------------ //

        public DdosConfig   Ddos           { get; set; } = new DdosConfig();

        /// <summary>Permitted HTTP methods — anything else → 405</summary>
        public string[]     AllowedMethods { get; set; } = { "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD" };

        /// <summary>Maximum Content-Length in bytes (default: 10 MB)</summary>
        public int          MaxBodySize    { get; set; } = 10 * 1024 * 1024;

        public RateLimitConfig RateLimit   { get; set; } = new RateLimitConfig();

        /// <summary>IPs / CIDR ranges that bypass all checks (never blocked)</summary>
        public string[]     Whitelist      { get; set; } = Array.Empty<string>();

        /// <summary>IPs / CIDR ranges that are always blocked</summary>
        public string[]     Blacklist      { get; set; } = Array.Empty<string>();

        /// <summary>URL paths that skip all WAF checks (exact prefix match)</summary>
        public string[]     BypassPaths    { get; set; } = { "/health", "/ping" };

        /// <summary>Trusted reverse-proxy IPs — enables X-Forwarded-For parsing</summary>
        public string[]     TrustedProxies { get; set; } = Array.Empty<string>();

        /// <summary>'reject' → send 403 and end; 'log-only' → log but let request through</summary>
        public string       Mode           { get; set; } = "reject";

        /// <summary>Log file path (must be writable by IIS app pool; should NOT be web-accessible)</summary>
        public string       LogPath        { get; set; } = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "App_Data", "waf.log");

        /// <summary>Block response format: 'json' or 'html'</summary>
        public string       ResponseType   { get; set; } = "json";

        /// <summary>
        /// Debug mode: log every request (pass + block) and add X-WAF-* response headers.
        /// Never enable in production — exposes internal rule names in headers.
        /// </summary>
        public bool         Debug          { get; set; } = false;
    }
}
