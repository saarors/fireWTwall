using System;
using System.Collections.Generic;

namespace FireWTWall.Detectors
{
    /// <summary>
    /// Detects Open Redirect attempts.
    /// </summary>
    public static class OpenRedirectDetector
    {
        private static readonly HashSet<string> RedirectParams = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "redirect", "return", "returnurl", "next", "url", "dest", "destination",
            "go", "goto", "target", "redir", "r", "u", "link", "forward",
            "location", "continue", "ref",
        };

        public static DetectorResult Scan(WafRequest request)
        {
            foreach (var source in new[] {
                ("query", request.Query),
                ("body",  request.Form)
            })
            {
                foreach (var kv in source.Item2)
                {
                    if (!RedirectParams.Contains(kv.Key)) continue;
                    if (IsAbsoluteRedirect(kv.Value))
                        return new DetectorResult("open-redirect", "high",
                            kv.Value.Length > 120 ? kv.Value.Substring(0, 120) : kv.Value,
                            source.Item1);
                }
            }
            return null;
        }

        private static bool IsAbsoluteRedirect(string value)
        {
            string v = value.TrimStart();
            return v.StartsWith("http://",  StringComparison.OrdinalIgnoreCase)
                || v.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                || v.StartsWith("//")
                || v.StartsWith("\\");
        }
    }
}
