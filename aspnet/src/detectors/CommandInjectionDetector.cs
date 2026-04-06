using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace FireWTWall.Detectors
{
    public static class CommandInjectionDetector
    {
        private static readonly (string Name, string Severity, Regex Pattern)[] Rules =
        {
            ("cmd-pipe",          "critical", new Regex(@"[|;`]\s*(?:ls|cat|whoami|id|uname|wget|curl|bash|sh|python|perl|ruby|nc|netcat|ncat)\b",  RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("cmd-subshell",      "critical", new Regex(@"\$\([^)]*\)|`[^`]*`",                                                                       RegexOptions.Compiled)),
            ("cmd-path-exec",     "critical", new Regex(@"/(?:bin|usr/bin|usr/local/bin)/\w+",                                                        RegexOptions.Compiled)),
            ("cmd-win-shell",     "critical", new Regex(@"(?:cmd\.exe|powershell(?:\.exe)?|wscript|cscript)\b",                                      RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("cmd-win-net",       "high",     new Regex(@"\bnet\s+(?:user|group|localgroup|share)\b",                                                 RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("cmd-win-reg",       "high",     new Regex(@"\breg(?:\.exe)?\s+(?:add|delete|query|export)",                                            RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("cmd-wget-curl",     "critical", new Regex(@"\b(?:wget|curl)\s+(?:https?|ftp)://",                                                      RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("cmd-base64-decode", "high",     new Regex(@"base64\s*(?:--decode|-d)\b",                                                               RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("cmd-redirection",   "high",     new Regex(@"(?:^|[^<])>{1,2}\s*/(?:etc|tmp|var|dev)",                                                  RegexOptions.Compiled)),
            ("cmd-python-exec",   "critical", new Regex(@"python[23]?\s+-[cC]\s+[""']?.*import|python[23]?\s+-[cC]\s+[""']?.*exec",                 RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("cmd-ruby-exec",     "critical", new Regex(@"ruby\s+-e\s+[""']?",                                                                       RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("cmd-perl-exec",     "critical", new Regex(@"perl\s+-e\s+[""']?",                                                                       RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("cmd-php-exec",      "critical", new Regex(@"php\s+-r\s+[""']?",                                                                        RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("cmd-netcat",        "critical", new Regex(@"\bnc\s+-[enlvz]|\bnetcat\b",                                                               RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("cmd-whoami",        "high",     new Regex(@"\bwhoami\b|\bid\b|\bpasswd\b",                                                             RegexOptions.IgnoreCase | RegexOptions.Compiled)),
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
