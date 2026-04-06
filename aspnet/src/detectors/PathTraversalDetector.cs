using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace FireWTWall.Detectors
{
    public static class PathTraversalDetector
    {
        private static readonly (string Name, string Severity, Regex Pattern)[] Rules =
        {
            ("path-traversal-dotdot",  "critical", new Regex(@"(?:\.\.[\\/]|[\\/]\.\.)",                      RegexOptions.Compiled)),
            ("path-traversal-encoded", "critical", new Regex(@"%2e%2e[%2f5c]",                                RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("path-traversal-unicode", "critical", new Regex(@"(?:%c0%ae|%c1%9c)",                            RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("path-null-byte",         "critical", new Regex(@"%00|\x00",                                     RegexOptions.Compiled)),
            ("path-etc-passwd",        "critical", new Regex(@"/etc/(?:passwd|shadow|hosts|group)\b",         RegexOptions.Compiled)),
            ("path-win-system",        "critical", new Regex(@"(?:c:|%systemroot%)[/\\]",                     RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("path-env-file",          "high",     new Regex(@"(?:^|/)\.env(?:\.|$)",                         RegexOptions.Compiled)),
            ("path-wp-config",         "high",     new Regex(@"wp-config\.php",                               RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("path-htaccess",          "high",     new Regex(@"\.htaccess\b",                                 RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("path-git-config",        "high",     new Regex(@"\.git[/\\]",                                   RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("path-ssh-keys",          "high",     new Regex(@"\.ssh[/\\]",                                   RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("path-proc-self",         "critical", new Regex(@"/proc/self/",                                  RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("path-php-wrappers",      "high",     new Regex(@"(?:php|zip|phar|data|expect|glob|file)://",   RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("path-php-filter",        "high",     new Regex(@"php://(?:filter|input|stdin)",                 RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("path-windows-root",      "high",     new Regex(@"[a-zA-Z]:\\|%SYSTEMROOT%|%WINDIR%",           RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("path-system32",          "critical", new Regex(@"windows[/\\]system32",                        RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("path-boot",              "critical", new Regex(@"/boot/grub|/boot/vmlinuz|/boot/initrd",       RegexOptions.IgnoreCase | RegexOptions.Compiled)),
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
