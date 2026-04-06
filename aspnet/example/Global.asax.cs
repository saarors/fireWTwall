using System;
using System.Web;

namespace FireWTWall.Example
{
    public class MvcApplication : HttpApplication
    {
        protected void Application_Start(object sender, EventArgs e)
        {
            // ----------------------------------------------------------------
            // Optional: customise WAF settings here.
            // All settings below show their defaults — uncomment to override.
            // ----------------------------------------------------------------

            // WafConfig.Current.Mode = "reject";       // or "log-only"
            // WafConfig.Current.Debug = false;
            // WafConfig.Current.ResponseType = "json"; // or "html"

            // WafConfig.Current.RateLimit.MaxRequests       = 100;
            // WafConfig.Current.RateLimit.WindowSec         = 60;
            // WafConfig.Current.RateLimit.BlockDurationSec  = 600;

            // WafConfig.Current.MaxBodySize = 10 * 1024 * 1024;

            // WafConfig.Current.Whitelist = new[] { "127.0.0.1", "192.168.1.0/24" };
            // WafConfig.Current.Blacklist = new[] { "1.2.3.4" };
            // WafConfig.Current.BypassPaths = new[] { "/health", "/ping" };

            // WafConfig.Current.TrustedProxies = new[] { "10.0.0.1" };

            // WafConfig.Current.AllowedMethods = new[]
            //     { "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD" };

            // WafBotConfigProvider.Config.BlockEmptyUserAgent = true;
        }
    }
}
