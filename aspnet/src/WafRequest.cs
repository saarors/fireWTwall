using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;

namespace FireWTWall
{
    /// <summary>
    /// Normalises and wraps the current HTTP request.
    /// All string values are URL-decoded (up to 3 passes) and null-byte stripped.
    /// </summary>
    public sealed class WafRequest
    {
        private static readonly Regex UnicodeEscape = new Regex(
            @"\\u([0-9a-fA-F]{4})",
            RegexOptions.Compiled);

        private readonly HttpContext _ctx;

        private string  _rawBody;
        private bool    _rawBodyRead;

        // Decoded collections (lazy-initialised)
        private Dictionary<string, string> _query;
        private Dictionary<string, string> _form;
        private Dictionary<string, string> _cookies;
        private Dictionary<string, string> _headers;

        public WafRequest(HttpContext context, string[] trustedProxies)
        {
            _ctx           = context;
            Method         = (context.Request.HttpMethod ?? "GET").ToUpperInvariant();
            Path           = context.Request.Path ?? "/";
            UserAgent      = context.Request.UserAgent ?? "";
            ContentLength  = context.Request.ContentLength;
            Ip             = ResolveIp(trustedProxies);
        }

        // ------------------------------------------------------------------ //
        // Properties
        // ------------------------------------------------------------------ //

        public string Method        { get; }
        public string Path          { get; }
        public string Ip            { get; }
        public string UserAgent     { get; }
        public int    ContentLength { get; }

        public Dictionary<string, string> Query
        {
            get { return _query ?? (_query = DecodeCollection(_ctx.Request.QueryString)); }
        }

        public Dictionary<string, string> Form
        {
            get { return _form ?? (_form = DecodeCollection(_ctx.Request.Form)); }
        }

        public Dictionary<string, string> Cookies
        {
            get
            {
                if (_cookies != null) return _cookies;
                _cookies = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (string key in _ctx.Request.Cookies)
                {
                    if (key != null)
                        _cookies[key] = DeepDecode(_ctx.Request.Cookies[key]?.Value ?? "");
                }
                return _cookies;
            }
        }

        public Dictionary<string, string> Headers
        {
            get
            {
                if (_headers != null) return _headers;
                _headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (string key in _ctx.Request.Headers)
                {
                    if (key != null)
                        _headers[key.ToLowerInvariant()] = _ctx.Request.Headers[key] ?? "";
                }
                return _headers;
            }
        }

        public string RawBody
        {
            get
            {
                if (_rawBodyRead) return _rawBody ?? "";
                _rawBodyRead = true;
                try
                {
                    var stream = _ctx.Request.InputStream;
                    if (stream.CanSeek) stream.Position = 0;
                    using (var reader = new StreamReader(stream, Encoding.UTF8, true, 4096, leaveOpen: true))
                    {
                        _rawBody = reader.ReadToEnd();
                    }
                    if (stream.CanSeek) stream.Position = 0;
                }
                catch
                {
                    _rawBody = "";
                }
                return _rawBody;
            }
        }

        // ------------------------------------------------------------------ //
        // Helpers
        // ------------------------------------------------------------------ //

        private string ResolveIp(string[] trustedProxies)
        {
            string remote = _ctx.Request.UserHostAddress ?? "0.0.0.0";

            if (trustedProxies == null || trustedProxies.Length == 0)
                return remote;

            if (!IpFilter.IpInList(remote, trustedProxies))
                return remote;

            string xff = _ctx.Request.Headers["X-Forwarded-For"] ?? "";
            if (xff == "") return remote;

            // Walk from right; the first non-trusted IP is the real client
            var parts = xff.Split(',');
            for (int i = parts.Length - 1; i >= 0; i--)
            {
                string candidate = parts[i].Trim();
                if (IsValidIp(candidate) && !IpFilter.IpInList(candidate, trustedProxies))
                    return candidate;
            }

            return remote;
        }

        private static bool IsValidIp(string s)
        {
            System.Net.IPAddress addr;
            return System.Net.IPAddress.TryParse(s, out addr);
        }

        private Dictionary<string, string> DecodeCollection(System.Collections.Specialized.NameValueCollection col)
        {
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string key in col)
            {
                if (key != null)
                    dict[key] = DeepDecode(col[key] ?? "");
            }
            return dict;
        }

        /// <summary>
        /// URL-decodes up to 3 passes, strips null bytes, and decodes HTML entities.
        /// Mirrors PHP Request::deepDecode().
        /// </summary>
        public static string DeepDecode(string value, int maxPasses = 3)
        {
            if (value == null) return "";

            // Normalise double-encoded percent signs (%2500 → %00)
            value = value.Replace("%2500", "%00");

            // Decode Unicode escape sequences (\uXXXX → char)
            value = UnicodeEscape.Replace(value, m =>
                ((char)Convert.ToInt32(m.Groups[1].Value, 16)).ToString());

            string prev = null;
            for (int i = 0; i < maxPasses; i++)
            {
                value = value.Replace("\x00", "");
                string decoded = Uri.UnescapeDataString(value.Replace("+", " "));
                if (decoded == prev) break;
                prev  = value;
                value = decoded;
            }

            return HttpUtility.HtmlDecode(value) ?? value;
        }
    }
}
