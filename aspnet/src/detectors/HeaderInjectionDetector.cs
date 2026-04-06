using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace FireWTWall.Detectors
{
    /// <summary>
    /// Detects CRLF injection and Host header injection.
    /// </summary>
    public static class HeaderInjectionDetector
    {
        private static readonly Regex CrlfPattern = new Regex(
            @"[\r\n]|%0[aAdD]|\\r|\\n",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static readonly Regex HostInjectionPattern = new Regex(
            @"[/?\r\n@#]",
            RegexOptions.Compiled);

        public static DetectorResult Scan(Dictionary<string, string> headers, string host)
        {
            // 1. CRLF injection in any header
            foreach (var kv in headers)
            {
                Match m = CrlfPattern.Match(kv.Value);
                if (m.Success)
                    return new DetectorResult("crlf-injection", "critical",
                        m.Value.Length > 120 ? m.Value.Substring(0, 120) : m.Value,
                        "header:" + kv.Key);
            }

            // 2. Host header injection
            if (!string.IsNullOrEmpty(host))
            {
                Match m = HostInjectionPattern.Match(host);
                if (m.Success)
                    return new DetectorResult("host-header-injection", "high",
                        m.Value.Length > 120 ? m.Value.Substring(0, 120) : m.Value,
                        "header:host");
            }

            return null;
        }
    }
}
