using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace FireWTWall.Detectors
{
    public static class XssDetector
    {
        private static readonly (string Name, string Severity, Regex Pattern)[] Rules =
        {
            ("xss-script-tag",       "critical", new Regex(@"<\s*script[\s>/]",                              RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("xss-javascript-proto", "critical", new Regex(@"javascript\s*:",                                RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("xss-vbscript-proto",   "critical", new Regex(@"vbscript\s*:",                                  RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("xss-data-uri",         "critical", new Regex(@"data\s*:\s*text/html",                          RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("xss-event-handler",    "high",     new Regex(@"\bon\w+\s*=",                                   RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("xss-iframe",           "high",     new Regex(@"<\s*iframe[\s>/]",                              RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("xss-object-embed",     "high",     new Regex(@"<\s*(?:object|embed)[\s>/]",                   RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("xss-svg",              "high",     new Regex(@"<\s*svg[\s>/]",                                 RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("xss-link-meta",        "medium",   new Regex(@"<\s*(?:link|meta)[\s>/]",                      RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("xss-expression",       "high",     new Regex(@"expression\s*\(",                               RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("xss-img-src",          "medium",   new Regex(@"<\s*img[^>]+src\s*=",                          RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("xss-srcdoc",           "high",     new Regex(@"srcdoc\s*=",                                   RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("xss-base-href",        "medium",   new Regex(@"<\s*base[\s>]",                                RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("xss-form-action",      "high",     new Regex(@"<\s*form[^>]+action\s*=\s*['""]?javascript",  RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("xss-dom-write",        "high",     new Regex(@"document\s*\.\s*(?:write|writeln)\s*\(",       RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("xss-inner-html",       "high",     new Regex(@"\.innerHTML\s*=",                              RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("xss-angularjs-bind",   "high",     new Regex(@"\{\{.*\}\}",                                   RegexOptions.Compiled)),
            ("xss-css-import",       "high",     new Regex(@"@import\s+url\s*\(",                           RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("xss-moz-binding",      "high",     new Regex(@"-moz-binding\s*:",                             RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("xss-meta-refresh",     "high",     new Regex(@"<meta[^>]+http-equiv\s*=\s*[""']?refresh",    RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("xss-link-import",      "high",     new Regex(@"<link[^>]+rel\s*=\s*[""']?import",            RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("xss-svg-animate",      "medium",   new Regex(@"<animate[^>]+attributeName",                   RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        };

        public static DetectorResult Scan(Dictionary<string, string> sources)
        {
            foreach (var kv in sources)
            {
                var r = MatchString(kv.Value, kv.Key);
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
                    return new DetectorResult(rule.Name, rule.Severity,
                        m.Value.Length > 120 ? m.Value.Substring(0, 120) : m.Value, label);
            }
            return null;
        }
    }
}
