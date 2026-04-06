using System;
using System.Collections.Generic;
using System.Web.Script.Serialization;

namespace FireWTWall.Detectors
{
    /// <summary>
    /// Detects Mass Assignment / Object Injection attempts.
    /// </summary>
    public static class MassAssignmentDetector
    {
        private static readonly HashSet<string> DangerousKeys = new HashSet<string>(StringComparer.Ordinal)
        {
            "__proto__", "constructor", "prototype",
            "__class__", "__type__", "_method", "_METHOD",
            "__destruct", "__wakeup", "__construct",
        };

        private static readonly JavaScriptSerializer _json = new JavaScriptSerializer();

        public static DetectorResult Scan(WafRequest request)
        {
            // 1. Flat query + body key scan
            foreach (var source in new[] {
                ("query", request.Query),
                ("body",  request.Form)
            })
            {
                foreach (var key in source.Item2.Keys)
                {
                    if (DangerousKeys.Contains(key))
                        return new DetectorResult("mass-assignment", "critical", key, source.Item1);
                }
            }

            // 2. JSON body — recursive key scan
            string raw = request.RawBody;
            if (!string.IsNullOrEmpty(raw))
            {
                try
                {
                    var decoded = _json.Deserialize<Dictionary<string, object>>(raw);
                    if (decoded != null)
                    {
                        var r = ScanKeys(decoded, "body");
                        if (r != null) return r;
                    }
                }
                catch { /* not JSON — ignore */ }
            }

            return null;
        }

        private static DetectorResult ScanKeys(Dictionary<string, object> data, string source)
        {
            foreach (var kv in data)
            {
                if (DangerousKeys.Contains(kv.Key))
                    return new DetectorResult("mass-assignment", "critical", kv.Key, source);

                if (kv.Value is Dictionary<string, object> nested)
                {
                    var r = ScanKeys(nested, source);
                    if (r != null) return r;
                }
            }
            return null;
        }
    }
}
