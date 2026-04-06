using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace FireWTWall.Detectors
{
    /// <summary>
    /// Detects Server-Side Template Injection (SSTI) attempts.
    /// </summary>
    public static class SstiDetector
    {
        private static readonly (string Id, string Severity, Regex Pattern)[] Rules =
        {
            ("ssti-python-class",       "critical", new Regex(@"\{\{.*__class__.*\}\}",                              RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("ssti-python-mro",         "critical", new Regex(@"\{\{.*__mro__.*\}\}",                               RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("ssti-python-subclasses",  "critical", new Regex(@"\{\{.*__subclasses__\s*\(\)",                       RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("ssti-python-popen",       "critical", new Regex(@"\{\{.*popen\s*\(|subprocess\s*\.",                  RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("ssti-python-globals",     "critical", new Regex(@"\{\{.*__globals__.*\}\}",                           RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("ssti-python-builtins",    "critical", new Regex(@"\{\{.*__builtins__.*\}\}",                          RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("ssti-twig-self",          "critical", new Regex(@"\{\{_self\.env\.",                                  RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("ssti-twig-filter",        "critical", new Regex(@"registerUndefinedFilterCallback",                   RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("ssti-freemarker",         "critical", new Regex(@"<#assign[^>]*Execute|freemarker\.template\.utility\.Execute", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("ssti-velocity",           "critical", new Regex(@"#set\s*\(\s*\$[a-z]+\s*=\s*[""']?\s*\$class|#set.*Runtime", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("ssti-smarty-php",         "critical", new Regex(@"\{php\}|\{/php\}",                                 RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("ssti-smarty-system",      "critical", new Regex(@"\{system\s*\(|\{passthru\s*\(",                    RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("ssti-erb",                "critical", new Regex(@"<%=\s*(system|`|%x|IO\.popen|exec)",               RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("ssti-java-runtime",       "critical", new Regex(@"\$\{.*Runtime.*exec|\$\{.*ProcessBuilder",         RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("ssti-ognl-expression",    "critical", new Regex(@"%\{#[a-zA-Z_]|%25\{#|\$\{#context\[",             RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("ssti-ognl-member",        "critical", new Regex(@"#_memberAccess|@java\.lang\.Runtime|new java\.lang\.ProcessBuilder", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("ssti-spring-classloader", "critical", new Regex(@"class\.module\.classLoader|class\.classLoader\.urls", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("ssti-tornado-import",     "critical", new Regex(@"\{%\s*import\s+os\s*%\}",                          RegexOptions.IgnoreCase | RegexOptions.Compiled)),
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
                    return new DetectorResult(rule.Id, rule.Severity,
                        m.Value.Length > 120 ? m.Value.Substring(0, 120) : m.Value, label);
            }
            return null;
        }
    }
}
