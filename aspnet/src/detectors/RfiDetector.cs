using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace FireWTWall.Detectors
{
    /// <summary>
    /// Detects Remote File Inclusion (RFI) attempts.
    /// </summary>
    public static class RfiDetector
    {
        private static readonly HashSet<string> FileParams = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "page", "file", "include", "require", "template", "view", "document",
            "folder", "root", "path", "pg", "style", "pdf", "layout", "conf",
            "config", "inc", "mod", "module", "load", "show",
        };

        private static readonly (string Id, string Severity, Regex Pattern)[] Rules =
        {
            ("rfi-http",       "critical", new Regex(@"^https?://",                                                   RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("rfi-ftp",        "critical", new Regex(@"^ftp://",                                                      RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("rfi-smb",        "critical", new Regex(@"^\\\\",                                                        RegexOptions.Compiled)),
            ("rfi-expect",     "critical", new Regex(@"^expect://",                                                   RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("rfi-data",       "critical", new Regex(@"^data:text/plain;base64,",                                     RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("rfi-log-poison", "critical", new Regex(@"/var/log/(apache|nginx|httpd|auth|syslog|mail)|/proc/self/environ", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
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
                    if (!FileParams.Contains(kv.Key)) continue;
                    foreach (var rule in Rules)
                    {
                        Match m = rule.Pattern.Match(kv.Value);
                        if (m.Success)
                            return new DetectorResult(rule.Id, rule.Severity,
                                m.Value.Length > 120 ? m.Value.Substring(0, 120) : m.Value,
                                source.Item1);
                    }
                }
            }
            return null;
        }
    }
}
