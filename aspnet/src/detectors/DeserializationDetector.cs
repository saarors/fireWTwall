using System.Text.RegularExpressions;

namespace FireWTWall.Detectors
{
    /// <summary>
    /// Detects insecure deserialization payloads (PHP, Java, Node.js).
    /// </summary>
    public static class DeserializationDetector
    {
        private static readonly (string Id, string Severity, Regex Pattern)[] Rules =
        {
            ("deser-php-object",  "critical", new Regex(@"O:\d+:""[a-zA-Z_\\]+""\:\d+:\{",         RegexOptions.Compiled)),
            ("deser-php-array",   "high",     new Regex(@"a:\d+:\{(?:i:\d+;|s:\d+:"")",            RegexOptions.Compiled)),
            ("deser-java-b64",    "critical", new Regex(@"rO0AB[XY]",                               RegexOptions.Compiled)),
            ("deser-java-hex",    "critical", new Regex(@"aced0005",                                RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("deser-node-serial", "critical", new Regex(@"\{""rce""\s*:\s*""_\$\$ND_FUNC\$\$_function", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        };

        public static DetectorResult Scan(WafRequest request)
        {
            // Check raw body first (catches binary/base64 payloads)
            string rawBody = request.RawBody;
            if (!string.IsNullOrEmpty(rawBody))
            {
                var r = MatchString(rawBody, "body");
                if (r != null) return r;
            }

            // Check query and cookies
            foreach (var source in new[] {
                ("query",   request.Query),
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
