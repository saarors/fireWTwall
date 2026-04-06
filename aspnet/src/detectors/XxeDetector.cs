using System.Text.RegularExpressions;

namespace FireWTWall.Detectors
{
    /// <summary>
    /// Detects XML External Entity (XXE) injection attempts.
    /// Only activates when the request body looks like XML.
    /// </summary>
    public static class XxeDetector
    {
        private static readonly Regex[] Patterns =
        {
            new Regex(@"<!DOCTYPE[^>]*\[",  RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"<!ENTITY[^>]*SYSTEM", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"<!ENTITY\s+%",      RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"SYSTEM\s+[""']",    RegexOptions.Compiled),
            new Regex(@"PUBLIC\s+[""']",    RegexOptions.Compiled),
            new Regex(@"<xi:include",       RegexOptions.IgnoreCase | RegexOptions.Compiled),
        };

        public static DetectorResult Scan(WafRequest request)
        {
            string body        = request.RawBody;
            string contentType = "";
            request.Headers.TryGetValue("content-type", out contentType);

            if (!IsXmlContent(contentType ?? "", body))
                return null;

            foreach (var pattern in Patterns)
            {
                if (pattern.IsMatch(body))
                {
                    string snippet = body.Length > 100 ? body.Substring(0, 100) : body;
                    return new DetectorResult("xxe-external-entity", "critical", snippet, "body");
                }
            }

            return null;
        }

        private static bool IsXmlContent(string contentType, string body)
        {
            if (contentType.ToLowerInvariant().Contains("xml")) return true;
            string prefix = body.TrimStart();
            return prefix.StartsWith("<?xml") || prefix.StartsWith("<!DOCTYPE");
        }
    }
}
