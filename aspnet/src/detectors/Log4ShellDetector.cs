using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Web;

namespace FireWTWall.Detectors
{
    /// <summary>
    /// Detects Log4Shell (CVE-2021-44228) and related Log4j JNDI injection attempts.
    /// Scans all HTTP headers, query params, body, and cookies.
    /// </summary>
    public static class Log4ShellDetector
    {
        private static readonly (string Id, string Severity, Regex Pattern)[] Rules =
        {
            ("log4shell-jndi",          "critical", new Regex(@"\$\{jndi\s*:",                                                       RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("log4shell-jndi-protocol", "critical", new Regex(@"\$\{jndi\s*:\s*(ldap|ldaps|rmi|dns|iiop|corba|nds|http)s?://",      RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("log4shell-obfusc-lower",  "critical", new Regex(@"\$\{.*lower.*j.*ndi|j\$\{.*\}ndi",                                  RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("log4shell-obfusc-upper",  "critical", new Regex(@"\$\{.*upper.*j.*ndi",                                               RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("log4shell-double-colon",  "critical", new Regex(@"\$\{\s*::-[jJ]\s*\}",                                               RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("log4shell-nested",        "critical", new Regex(@"\$\{[^}]*\$\{[^}]*\}[^}]*jndi",                                    RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        };

        public static DetectorResult Scan(WafRequest request)
        {
            // Scan all HTTP headers
            foreach (var kv in request.Headers)
            {
                var r = MatchString(kv.Value, "header");
                if (r != null) return r;
            }

            // Scan query, body, cookies
            foreach (var source in new[] {
                ("query",   request.Query),
                ("body",    request.Form),
                ("cookies", request.Cookies)
            })
            {
                foreach (var kv in source.Item2)
                {
                    var r = MatchString(kv.Value, source.Item1);
                    if (r != null) return r;
                }
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
