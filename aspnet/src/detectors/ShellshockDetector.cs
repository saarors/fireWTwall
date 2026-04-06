using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace FireWTWall.Detectors
{
    /// <summary>
    /// Detects Shellshock (CVE-2014-6271 / CVE-2014-7169) exploitation attempts.
    /// Shellshock payloads are delivered via HTTP headers.
    /// </summary>
    public static class ShellshockDetector
    {
        private static readonly (string Id, string Severity, Regex Pattern)[] Rules =
        {
            ("shellshock-func",    "critical", new Regex(@"\(\s*\)\s*\{\s*[^}]*\}\s*;",  RegexOptions.Compiled)),
            ("shellshock-env-cmd", "critical", new Regex(@"\(\s*\)\s*\{\s*:;\s*\}\s*;",  RegexOptions.Compiled)),
        };

        public static DetectorResult Scan(WafRequest request)
        {
            foreach (var kv in request.Headers)
            {
                var r = MatchString(kv.Value, "header");
                if (r != null) return r;
            }
            return null;
        }

        private static DetectorResult MatchString(string value, string label)
        {
            foreach (var rule in Rules)
            {
                Match m = rule.Pattern.Match(value);
                if (m.Success)
                    return new DetectorResult(rule.Id, rule.Severity,
                        m.Value.Length > 120 ? m.Value.Substring(0, 120) : m.Value, label);
            }
            return null;
        }
    }
}
