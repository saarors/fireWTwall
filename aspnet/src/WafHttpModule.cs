using System;
using System.Web;
using FireWTWall.Detectors;

namespace FireWTWall
{
    /// <summary>
    /// ASP.NET HttpModule that runs the WAF pipeline on every incoming request.
    ///
    /// Registration (add to Web.config):
    ///
    ///   &lt;system.webServer&gt;
    ///     &lt;modules&gt;
    ///       &lt;add name="FireWTWallModule" type="FireWTWall.WafHttpModule" /&gt;
    ///     &lt;/modules&gt;
    ///   &lt;/system.webServer&gt;
    ///
    ///   &lt;!-- For IIS Classic mode, also add: --&gt;
    ///   &lt;system.web&gt;
    ///     &lt;httpModules&gt;
    ///       &lt;add name="FireWTWallModule" type="FireWTWall.WafHttpModule" /&gt;
    ///     &lt;/httpModules&gt;
    ///   &lt;/system.web&gt;
    ///
    /// Override defaults in Global.asax before first request:
    ///
    ///   WafConfig.Current.Mode = "log-only";
    ///   WafConfig.Current.RateLimit.MaxRequests = 200;
    ///   WafBotConfigProvider.Config.BlockEmptyUserAgent = false;
    /// </summary>
    public sealed class WafHttpModule : IHttpModule
    {
        public void Init(HttpApplication context)
        {
            context.BeginRequest += OnBeginRequest;
        }

        private void OnBeginRequest(object sender, EventArgs e)
        {
            var app = (HttpApplication)sender;
            try
            {
                var waf = new WAF(WafConfig.Current, WafBotConfigProvider.Config);
                waf.Run(app.Context);
            }
            catch (System.Threading.ThreadAbortException)
            {
                // Thrown by Response.End() on block — expected, do not re-throw
            }
            catch (Exception ex)
            {
                // Log WAF internal errors to Application event log; never crash the app
                try
                {
                    System.Diagnostics.EventLog.WriteEntry(
                        "FireWTWall",
                        "WAF internal error: " + ex.Message,
                        System.Diagnostics.EventLogEntryType.Warning);
                }
                catch { /* swallow */ }
            }
        }

        public void Dispose() { }
    }

    /// <summary>
    /// Singleton holder for the bot configuration.
    /// Override in Application_Start to customise the bot list.
    /// </summary>
    public static class WafBotConfigProvider
    {
        private static BotConfig _config;
        private static readonly object _lock = new object();

        public static BotConfig Config
        {
            get
            {
                if (_config != null) return _config;
                lock (_lock)
                {
                    if (_config == null)
                        _config = LoadDefaultBotConfig();
                }
                return _config;
            }
            set { _config = value; }
        }

        private static BotConfig LoadDefaultBotConfig()
        {
            return new BotConfig
            {
                BlockEmptyUserAgent = true,
                Blocked = new[]
                {
                    "sqlmap", "nikto", "masscan", "zgrab", "dirbuster", "dirb",
                    "gobuster", "wfuzz", "nmap", "Nmap Scripting Engine",
                    "hydra", "metasploit", "havij",
                    "acunetix", "nessus", "openvas", "w3af", "skipfish", "arachni",
                    "vega", "burpsuite", "ZmEu", "libwww-perl", "lwp-trivial",
                    "binlar", "BlackWidow", "BlowFish", "CazoodleBot", "comodo",
                    "DISCo", "dotbot", "EmailSiphon", "EmailWolf", "ExaBot",
                    "flicky", "larbin", "LeechFTP", "Niki-Bot", "PageGrabber",
                    "SurveyBot", "webcollage", "Webster", "Zeus", "zmeu",
                    "obot", "psbot", "python-requests/2", "python-urllib", "python-httpx",
                    "Go-http-client/1",
                    "ffuf", "nuclei", "interactsh",
                    "qualysguard", "tenable", "appscan", "webscarab",
                    "pangolin", "sqlninja",
                    "shodan", "censys", "binaryedge", "criminalip",
                    "shadowserver", "grayhatwarfare",
                    "medusa",
                    "golismero", "joomscan", "wpscan", "droopescan",
                    "msf/", "msfconsole", "msfpayload", "jndi-exploit", "log4j-scanner",
                    "interactsh-client", "routersploit", "beef-", "xsser", "fimap",
                    "grabber", "uniscan", "vega/", "paros", "websecurify", "n-stealth",
                    "webinspect", "ibm appscan", "hp webinspect", "dotdotpwn", "jexboss",
                    "commix", "tplmap", "ysoserial", "nabuu",
                    "curl", "wget", "lynx", "elinks", "w3m", "fetch", "telnet",
                    "nc", "netcat", "ncat", "socat",
                    "insomnia", "postman", "apigee", "restclient", "httpie", "xh",
                    "aria2", "axel", "getright", "flashget",
                },
                Allowed = new[]
                {
                    "Googlebot", "Bingbot", "Slurp", "DuckDuckBot", "Baiduspider",
                    "YandexBot", "Sogou", "facebot", "ia_archiver",
                },
            };
        }
    }
}
