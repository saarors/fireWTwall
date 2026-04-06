using System;
using System.Web;
using System.Web.UI;

namespace FireWTWall.Example
{
    public partial class DefaultPage : Page
    {
        protected string BaseUrl   { get; private set; }
        protected string ClientIp  { get; private set; }
        protected string QueryString { get; private set; }

        protected void Page_Load(object sender, EventArgs e)
        {
            string scheme = Request.IsSecureConnection ? "https" : "http";
            string path   = Request.Url.AbsolutePath;
            BaseUrl       = scheme + "://" + Request.Url.Host + path;
            ClientIp      = HttpUtility.HtmlEncode(Request.UserHostAddress ?? "unknown");
            QueryString   = HttpUtility.HtmlEncode(Request.QueryString.ToString());
        }
    }
}
