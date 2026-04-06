using System;
using System.Collections.Generic;
using System.Web;
using System.Web.Script.Serialization;

namespace FireWTWall
{
    /// <summary>
    /// Renders block responses and terminates the request.
    /// </summary>
    public static class WafResponse
    {
        private static readonly Dictionary<string, string> SecurityHeaders = new Dictionary<string, string>
        {
            ["X-Content-Type-Options"]            = "nosniff",
            ["X-Frame-Options"]                   = "SAMEORIGIN",
            ["X-XSS-Protection"]                  = "1; mode=block",
            ["Referrer-Policy"]                   = "strict-origin-when-cross-origin",
            ["Cross-Origin-Opener-Policy"]        = "same-origin",
            ["Cross-Origin-Resource-Policy"]      = "same-origin",
            ["Cache-Control"]                     = "no-store",
            ["Strict-Transport-Security"]         = "max-age=31536000; includeSubDomains; preload",
            ["Content-Security-Policy"]           = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
            ["X-Permitted-Cross-Domain-Policies"] = "none",
        };

        private static readonly JavaScriptSerializer _json = new JavaScriptSerializer();

        /// <summary>Send a block response and end the request.</summary>
        public static void Block(HttpContext ctx, string rule, int statusCode = 403, string type = "json")
        {
            var resp = ctx.Response;
            resp.StatusCode = statusCode;
            SendSecurityHeaders(ctx);
            resp.Headers.Remove("X-Powered-By");
            resp.Headers.Remove("X-AspNet-Version");
            resp.Headers.Remove("Server");

            if (type == "json")
            {
                resp.ContentType = "application/json; charset=utf-8";
                resp.Write(_json.Serialize(new
                {
                    blocked = true,
                    rule    = rule,
                    message = "Request blocked by WAF",
                }));
            }
            else
            {
                resp.ContentType = "text/html; charset=utf-8";
                string safeRule = HttpUtility.HtmlEncode(rule);
                resp.Write($@"<!DOCTYPE html>
<html lang=""en"">
<head><meta charset=""UTF-8""><title>403 Blocked</title>
<style>
body{{font-family:sans-serif;display:flex;align-items:center;justify-content:center;
     height:100vh;margin:0;background:#f4f4f4}}
.box{{text-align:center;padding:2rem;background:#fff;border-radius:8px;
     box-shadow:0 2px 8px rgba(0,0,0,.1)}}
h1{{color:#c0392b}}code{{background:#eee;padding:2px 6px;border-radius:3px}}
</style></head>
<body><div class=""box"">
<h1>&#x1F6AB; Access Blocked</h1>
<p>Your request was blocked by the web application firewall.</p>
<p>Rule: <code>{safeRule}</code></p>
</div></body></html>");
            }

            resp.End();
        }

        /// <summary>Send a Method Not Allowed response.</summary>
        public static void MethodNotAllowed(HttpContext ctx, string[] allowedMethods)
        {
            ctx.Response.AddHeader("Allow", string.Join(", ", allowedMethods));
            Block(ctx, "method-not-allowed", 405);
        }

        /// <summary>Send a Rate Limit Exceeded response.</summary>
        public static void TooManyRequests(HttpContext ctx, int retryAfter, string type = "json")
        {
            ctx.Response.AddHeader("Retry-After", retryAfter.ToString());
            ctx.Response.StatusCode = 429;
            SendSecurityHeaders(ctx);

            if (type == "json")
            {
                ctx.Response.ContentType = "application/json; charset=utf-8";
                ctx.Response.Write(_json.Serialize(new
                {
                    blocked    = true,
                    rule       = "rate-limit",
                    message    = "Too many requests",
                    retryAfter = retryAfter,
                }));
            }
            else
            {
                ctx.Response.Write($"<h1>429 Too Many Requests</h1><p>Retry after {retryAfter} seconds.</p>");
            }

            ctx.Response.End();
        }

        /// <summary>Append security headers to all responses (called for clean/passing requests).</summary>
        public static void SendSecurityHeaders(HttpContext ctx)
        {
            var resp = ctx.Response;
            foreach (var kv in SecurityHeaders)
            {
                resp.Headers[kv.Key] = kv.Value;
            }
        }
    }
}
