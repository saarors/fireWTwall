using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace FireWTWall.Detectors
{
    /// <summary>
    /// Detects LDAP Injection attempts.
    /// </summary>
    public static class LdapInjectionDetector
    {
        private static readonly (string Id, string Severity, Regex Pattern)[] Rules =
        {
            ("ldap-wildcard-bypass", "high",     new Regex(@"\*\)\s*\(\s*[a-z]+=\*|^\*$",                    RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("ldap-injection-paren", "critical", new Regex(@"\*\)\s*\(\||\*\)\s*\(&",                        RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("ldap-injection-null",  "high",     new Regex(@"\x00|%00.*uid|uid.*%00",                        RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("ldap-injection-uid",   "critical", new Regex(@"\*\s*\)\s*\(\s*uid\s*=\s*\*",                  RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("ldap-injection-admin", "critical", new Regex(@"\*\)\s*\(\s*cn\s*=\s*admin|\)\s*\(&\s*\(password", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("ldap-injection-encode","high",     new Regex(@"\*28|\*29|\*00|\*2a",                           RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        };

        public static DetectorResult Scan(WafRequest request)
        {
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
