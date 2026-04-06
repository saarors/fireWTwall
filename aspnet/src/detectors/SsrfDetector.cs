using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace FireWTWall.Detectors
{
    /// <summary>
    /// Detects Server-Side Request Forgery (SSRF) attempts.
    /// </summary>
    public static class SsrfDetector
    {
        private static readonly HashSet<string> UrlParams = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "url", "redirect", "return", "callback", "next", "dest", "destination",
            "src", "source", "uri", "link", "href", "proxy", "forward", "returnurl",
            "goto", "target", "redir", "r", "u",
        };

        private static readonly Regex[] PrivateIpPatterns =
        {
            new Regex(@"^127\.",        RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"^10\.",         RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"^172\.(1[6-9]|2[0-9]|3[01])\.", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"^192\.168\.",   RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"^0\.0\.0\.0",   RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"^::1$",         RegexOptions.IgnoreCase | RegexOptions.Compiled),
        };

        private static readonly Regex[] MetadataPatterns =
        {
            new Regex(@"169\.254\.169\.254",     RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"metadata\.google\.internal", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"metadata\.azure\.com",   RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"100\.100\.100\.200",      RegexOptions.IgnoreCase | RegexOptions.Compiled),
        };

        private static readonly Regex[] SchemePatterns =
        {
            new Regex(@"^file://",   RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"^gopher://", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"^dict://",   RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"^ldap://",   RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"^tftp://",   RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"^ftp://",    RegexOptions.IgnoreCase | RegexOptions.Compiled),
        };

        public static DetectorResult Scan(WafRequest request)
        {
            foreach (var source in new[] {
                ("query", request.Query),
                ("body",  request.Form)
            })
            {
                foreach (var kv in source.Item2)
                {
                    if (!UrlParams.Contains(kv.Key)) continue;
                    if (IsSuspicious(kv.Value))
                        return new DetectorResult("ssrf-private-ip", "critical",
                            kv.Value.Length > 120 ? kv.Value.Substring(0, 120) : kv.Value,
                            source.Item1);
                }
            }
            return null;
        }

        private static bool IsSuspicious(string value)
        {
            string host = ExtractHost(value);

            foreach (var p in PrivateIpPatterns)
                if (host.Length > 0 && p.IsMatch(host)) return true;

            foreach (var p in MetadataPatterns)
                if (p.IsMatch(value)) return true;

            foreach (var p in SchemePatterns)
                if (p.IsMatch(value.TrimStart())) return true;

            return false;
        }

        private static string ExtractHost(string value)
        {
            try
            {
                var uri = new Uri(value);
                return uri.Host;
            }
            catch
            {
                int end = value.IndexOfAny(new[] { '/', '?', '#', ':', '\0' });
                return end >= 0 ? value.Substring(0, end) : value;
            }
        }
    }
}
