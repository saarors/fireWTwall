using System.Text.RegularExpressions;
using System.Web;

namespace FireWTWall.Detectors
{
    /// <summary>
    /// Detects NoSQL Injection attempts (primarily MongoDB operator injection).
    /// </summary>
    public static class NoSqlInjectionDetector
    {
        private static readonly (string Id, string Severity, Regex Pattern)[] Rules =
        {
            ("nosql-operator-ne",    "high",     new Regex(@"\[\s*\$ne\s*\]|""\s*\$ne\s*""\s*:",    RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("nosql-operator-gt",    "high",     new Regex(@"\[\s*\$gt\s*\]|""\s*\$gt\s*""\s*:",    RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("nosql-operator-lt",    "high",     new Regex(@"\[\s*\$lt\s*\]|""\s*\$lt\s*""\s*:",    RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("nosql-operator-where", "critical", new Regex(@"""\s*\$where\s*""\s*:",               RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("nosql-operator-regex", "high",     new Regex(@"\[\s*\$regex\s*\]|""\s*\$regex\s*""\s*:", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("nosql-operator-or",    "medium",   new Regex(@"""\s*\$or\s*""\s*:\s*\[",             RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("nosql-operator-expr",  "high",     new Regex(@"""\s*\$expr\s*""\s*:",               RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("nosql-func-sleep",     "critical", new Regex(@"""\s*\$where\s*"".*sleep\s*\(",       RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        };

        private static readonly Regex RawQsPattern = new Regex(
            @"\[\s*\$(ne|gt|lt|gte|lte|in|nin|regex|where|exists)\s*\]",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public static DetectorResult Scan(WafRequest request)
        {
            // Check raw query string for bracket-notation operators
            string rawQs = HttpContext.Current?.Request?.QueryString?.ToString() ?? "";
            if (!string.IsNullOrEmpty(rawQs))
            {
                Match m = RawQsPattern.Match(rawQs);
                if (m.Success)
                    return new DetectorResult("nosql-operator-raw-qs", "high",
                        m.Value.Length > 120 ? m.Value.Substring(0, 120) : m.Value, "query");
            }

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
