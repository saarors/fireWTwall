using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace FireWTWall
{
    /// <summary>
    /// Appends structured NDJSON entries to the WAF log file.
    /// Uses a file lock to ensure safe concurrent writes.
    /// </summary>
    public sealed class WafLogger
    {
        private readonly string _logPath;
        private static readonly JavaScriptSerializer _json = new JavaScriptSerializer();
        private static readonly object _fileLock = new object();

        public WafLogger(string logPath)
        {
            _logPath = logPath;
            string dir = Path.GetDirectoryName(logPath);
            if (dir != null && !Directory.Exists(dir))
            {
                try { Directory.CreateDirectory(dir); } catch { /* best-effort */ }
            }
        }

        public void LogPass(string ip, string method, string path,
                            string userAgent = "", string requestId = null, double? durationMs = null)
        {
            var entry = new System.Collections.Generic.Dictionary<string, object>
            {
                ["timestamp"] = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
                ["requestId"] = requestId ?? RandomHex(8),
                ["result"]    = "passed",
                ["ip"]        = ip,
                ["method"]    = method,
                ["path"]      = path,
            };
            if (!string.IsNullOrEmpty(userAgent)) entry["userAgent"]  = userAgent;
            if (durationMs.HasValue)              entry["durationMs"] = Math.Round(durationMs.Value, 3);

            Append(_json.Serialize(entry));
        }

        public void LogBlock(string ip, string method, string path,
                             string rule, string matched = "", string source = "",
                             string severity = "medium", string userAgent = "",
                             string requestId = null, double? durationMs = null)
        {
            var entry = new System.Collections.Generic.Dictionary<string, object>
            {
                ["timestamp"] = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
                ["requestId"] = requestId ?? RandomHex(8),
                ["result"]    = "blocked",
                ["ip"]        = ip,
                ["method"]    = method,
                ["path"]      = path,
                ["rule"]      = rule,
                ["severity"]  = severity,
            };
            if (!string.IsNullOrEmpty(source))    entry["source"]    = source;
            if (!string.IsNullOrEmpty(matched))   entry["matched"]   = matched.Length > 120 ? matched.Substring(0, 120) : matched;
            if (!string.IsNullOrEmpty(userAgent)) entry["userAgent"] = userAgent;
            if (durationMs.HasValue)              entry["durationMs"] = Math.Round(durationMs.Value, 3);

            Append(_json.Serialize(entry));
        }

        private void Append(string line)
        {
            try
            {
                lock (_fileLock)
                {
                    File.AppendAllText(_logPath, line + "\n", Encoding.UTF8);
                }
            }
            catch { /* best-effort — never throw from logger */ }
        }

        private static string RandomHex(int bytes)
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] buf = new byte[bytes];
                rng.GetBytes(buf);
                return BitConverter.ToString(buf).Replace("-", "").ToLowerInvariant();
            }
        }
    }
}
