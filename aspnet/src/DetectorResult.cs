using System;

namespace FireWTWall
{
    /// <summary>
    /// Returned by a detector when a threat pattern is matched.
    /// </summary>
    public sealed class DetectorResult
    {
        public string Rule     { get; }
        public string Severity { get; }
        public string Matched  { get; }
        public string Source   { get; }

        public DetectorResult(string rule, string severity, string matched, string source)
        {
            Rule     = rule;
            Severity = severity;
            Matched  = matched  != null && matched.Length  > 120 ? matched.Substring(0, 120)  : (matched  ?? "");
            Source   = source   ?? "";
        }
    }
}
