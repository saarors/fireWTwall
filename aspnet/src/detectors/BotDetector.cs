using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace FireWTWall.Detectors
{
    public sealed class BotDetector
    {
        private readonly List<Regex> _blockedPatterns  = new List<Regex>();
        private readonly List<Regex> _allowedPatterns  = new List<Regex>();
        private readonly bool        _blockEmptyUA;

        private static readonly Regex[] SuspiciousPatterns =
        {
            new Regex(@"^(curl|wget|python|perl|ruby|php|java|go|node)[\s/\-]", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"^libcurl",                RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"^HTTPClient",             RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"^Apache-HttpClient",      RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"^OkHttpClient",           RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"^java\.net\.URLConnection",RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"^scrapy",                 RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"^mechanize",              RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"^urllib",                 RegexOptions.IgnoreCase | RegexOptions.Compiled),
        };

        public BotDetector(BotConfig config)
        {
            foreach (var s in config.Blocked ?? Array.Empty<string>())
                _blockedPatterns.Add(new Regex(Regex.Escape(s), RegexOptions.IgnoreCase | RegexOptions.Compiled));

            foreach (var s in config.Allowed ?? Array.Empty<string>())
                _allowedPatterns.Add(new Regex(Regex.Escape(s), RegexOptions.IgnoreCase | RegexOptions.Compiled));

            _blockEmptyUA = config.BlockEmptyUserAgent;
        }

        /// <summary>Returns a DetectorResult if the UA is suspicious, or null if it passes.</summary>
        public DetectorResult Check(string userAgent)
        {
            if (string.IsNullOrEmpty(userAgent))
            {
                if (_blockEmptyUA)
                    return new DetectorResult("missing-user-agent", "high", "", "user-agent");
                return null;
            }

            // Allowed bots always pass
            foreach (var p in _allowedPatterns)
                if (p.IsMatch(userAgent)) return null;

            // Check blocklist
            foreach (var p in _blockedPatterns)
            {
                Match m = p.Match(userAgent);
                if (m.Success)
                    return new DetectorResult("bad-bot", "high",
                        m.Value.Length > 120 ? m.Value.Substring(0, 120) : m.Value, "user-agent");
            }

            // Check suspicious programmatic patterns
            foreach (var p in SuspiciousPatterns)
            {
                Match m = p.Match(userAgent);
                if (m.Success)
                    return new DetectorResult("suspicious-automation", "medium",
                        m.Value.Length > 120 ? m.Value.Substring(0, 120) : m.Value, "user-agent");
            }

            return null;
        }
    }

    public sealed class BotConfig
    {
        public string[] Blocked              { get; set; } = Array.Empty<string>();
        public string[] Allowed              { get; set; } = Array.Empty<string>();
        public bool     BlockEmptyUserAgent  { get; set; } = true;
    }
}
