# XSS Rules

The WAF applies 29 XSS rules. Rules are evaluated in order; the first match blocks the request.

**Scanned sources:** query params, request body, URL path, cookies.

---

## Script injection (critical)

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `xss-script-tag` | `<script` | `<script>alert(1)</script>` | Direct JavaScript execution in any HTML context |
| `xss-javascript-proto` | `javascript:` | `<a href="javascript:alert(1)">click</a>` | Executes JS in href, src, action and other URL attributes |
| `xss-vbscript-proto` | `vbscript:` | `<a href="vbscript:msgbox(1)">click</a>` | Legacy IE VBScript execution via URL protocol |
| `xss-data-uri` | `data:text/html` | `<iframe src="data:text/html,<script>alert(1)</script>">` | Embeds an HTML page inline via data URI |

```bash
curl "http://localhost:3000/?q=<script>alert(1)</script>"
curl "http://localhost:3000/?href=javascript:alert(document.cookie)"
```

---

## Event handlers (high)

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `xss-event-handler` | `on\w+=` | `<img src=x onerror=alert(1)>` | HTML event attributes execute JS on user interaction or error |

Event handler examples that trigger this rule:
- `onload=`, `onerror=`, `onclick=`, `onmouseover=`
- `onfocus=`, `onblur=`, `oninput=`, `onchange=`
- Any attribute beginning with `on` followed by word characters and `=`

```bash
curl "http://localhost:3000/?q=<img+src=x+onerror=alert(1)>"
```

---

## Dangerous HTML elements (high)

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `xss-iframe` | `<iframe` | `<iframe src="https://evil.com">` | Embeds external content; can be used for clickjacking or phishing |
| `xss-object-embed` | `<object` / `<embed` | `<object data="data:text/html,...">` | Loads plugins or external objects that can execute code |
| `xss-svg` | `<svg` | `<svg onload=alert(1)>` | SVG elements can contain event handlers and scripts |
| `xss-srcdoc` | `srcdoc=` | `<iframe srcdoc="<script>alert(1)</script>">` | Embeds an HTML document inline in an iframe |
| `xss-form-action` | `<form action=javascript:` | `<form action="javascript:alert(1)">` | Form action with javascript: protocol |

```bash
curl "http://localhost:3000/?q=<svg+onload=alert(1)>"
curl "http://localhost:3000/?q=<iframe+srcdoc='<script>alert(1)</script>'>"
```

---

## DOM sinks (high)

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `xss-dom-write` | `document.write(` / `document.writeln(` | `document.write('<script>'+data+'</script>')` | Writes HTML directly into the document, executing injected scripts |
| `xss-inner-html` | `.innerHTML=` | `el.innerHTML = userInput` | Sets HTML content, interpreting any injected tags and handlers |
| `xss-location-href` | `location.href = javascript:` / `window.location = javascript:` | `location.href='javascript:alert(1)'` | Navigates to a javascript: URL, executing code |

---

## AngularJS (high)

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `xss-angularjs-bind` | `{{...}}` | `{{constructor.constructor('alert(1)')()}}` | AngularJS template expressions are evaluated as JavaScript in ng-app contexts |

```bash
curl "http://localhost:3000/?name={{constructor.constructor('alert(1)')()}}"
```

---

## CSS-based XSS (high — v2 rules)

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `xss-css-import` | `@import url(` | `@import url('https://evil.com/malicious.css')` | CSS imports can load external stylesheets containing -moz-binding or expression() |
| `xss-moz-binding` | `-moz-binding:` | `-moz-binding: url('https://evil.com/xss.xml#xss')` | Firefox XBL binding executes arbitrary JavaScript via CSS |
| `xss-style-attr` | `style="...expression/url/javascript"` | `style="expression(alert(1))"` | IE CSS expression() function executes JavaScript |

---

## Meta / redirect injection (high — v2 rules)

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `xss-meta-refresh` | `<meta http-equiv="refresh"` | `<meta http-equiv="refresh" content="0;url=javascript:alert(1)">` | Redirects user to a javascript: URL via meta tag |
| `xss-link-import` | `<link rel="import"` | `<link rel="import" href="/attacker.html">` | HTML imports load external documents with full document permissions |
| `xss-form-action-js` | `<form action=javascript:` | `<form action="javascript:alert(1)">` | Form submission executes JavaScript |
| `xss-srcset` | `srcset=javascript:` | `<img srcset="javascript:alert(1)">` | srcset attribute with javascript: protocol |

---

## Medium severity

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `xss-link-meta` | `<link` / `<meta` | `<link rel="stylesheet" href="evil.css">` | Can load external resources or control page behavior |
| `xss-img-src` | `<img src=` | `<img src="x" onerror="alert(1)">` | Image tags with src attribute; often combined with onerror |
| `xss-base-href` | `<base` | `<base href="https://evil.com/">` | Overrides base URL for all relative links on the page |
| `xss-html-import` | `<import` / `<template` | `<template><script>...` | HTML template elements can contain deferred scripts |
| `xss-template-literal` | `` `${...}` `` | `` `<img src=${userInput}>` `` | Template literals with expressions used in dangerous DOM operations |
| `xss-svg-animate` | `<animate attributeName` | `<animate attributeName="href" values="javascript:alert(1)">` | SVG animation can set href to a javascript: URL |
| `xss-base-href-tag` | `<base href` | `<base href="//evil.com/">` | Protocol-relative base URL hijacks all relative links |
