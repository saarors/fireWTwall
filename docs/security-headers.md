# Security Headers

The WAF adds the following headers to **every response** regardless of whether the request is blocked or passed. Headers are set in stage 1 of the middleware pipeline, before any rule evaluation.

---

## All headers

### Strict-Transport-Security (HSTS)

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Protects against:** Protocol downgrade attacks (HTTP hijacking), SSL-stripping man-in-the-middle.

Instructs browsers to only access the site over HTTPS for the next year (31536000 seconds). `includeSubDomains` applies the policy to all subdomains. `preload` is required for HSTS preload list submission.

**Browser support:** All modern browsers (Chrome 4+, Firefox 4+, Safari 7+, Edge 12+).

**Customize (Node.js):**
```js
// In middleware/securityHeaders.js, adjust max-age or remove preload directive
res.setHeader('Strict-Transport-Security', 'max-age=86400');
```

---

### Content-Security-Policy (CSP)

```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'
```

**Protects against:** Cross-site scripting (XSS), clickjacking, data injection attacks.

Directive breakdown:
- `default-src 'self'` — all resources must be same-origin by default
- `script-src 'self'` — scripts may only load from the same origin
- `object-src 'none'` — no Flash, Java applets, or other plugins
- `base-uri 'self'` — prevents `<base href>` hijacking
- `frame-ancestors 'none'` — prevents framing (equivalent to `X-Frame-Options: DENY`)

**Browser support:** All modern browsers. Internet Explorer has partial support.

**Customize (Node.js):** If your application loads scripts, styles, or fonts from external CDNs, you must relax the CSP accordingly:

```js
res.setHeader('Content-Security-Policy',
  "default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' https://fonts.googleapis.com"
);
```

---

### X-Content-Type-Options

```
X-Content-Type-Options: nosniff
```

**Protects against:** MIME-type sniffing — browsers guessing content type from body content rather than declared `Content-Type`. Prevents script execution of files served with non-script MIME types.

**Browser support:** All modern browsers.

---

### X-Frame-Options

```
X-Frame-Options: SAMEORIGIN
```

**Protects against:** Clickjacking — embedding your site in an iframe on an attacker-controlled page.

`SAMEORIGIN` allows framing by pages on the same origin. The CSP `frame-ancestors 'none'` directive above is more restrictive (denies all framing) and takes precedence in browsers that support CSP Level 2. Both headers are sent for compatibility with older browsers.

**Browser support:** All browsers including IE8+.

---

### X-XSS-Protection

```
X-XSS-Protection: 1; mode=block
```

**Protects against:** Reflected XSS in older browsers that have a built-in XSS auditor (primarily IE, older Chrome/Safari).

Note: Modern browsers (Chrome 78+) have removed the XSS auditor. This header is sent for compatibility with legacy browsers. CSP is the effective XSS mitigation for modern browsers.

---

### Referrer-Policy

```
Referrer-Policy: strict-origin-when-cross-origin
```

**Protects against:** Leaking full URL paths (which may contain tokens, IDs, or sensitive parameters) in the `Referer` header to third-party sites.

Behavior:
- Same-origin requests: full URL in Referer
- Cross-origin requests to HTTPS: only origin (e.g., `https://yoursite.com`)
- Cross-origin requests to HTTP (downgrade): no Referer sent

**Browser support:** Chrome 52+, Firefox 52+, Safari 12.1+.

---

### Permissions-Policy

```
Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()
```

**Protects against:** Malicious scripts silently accessing device APIs (camera, microphone, geolocation) or FLoC tracking.

Each `()` means "disabled for all origins including same-origin." Adjust if your application uses any of these APIs.

**Browser support:** Chrome 74+ (as Feature-Policy), Chrome 88+ (as Permissions-Policy). Limited Firefox/Safari support.

**Customize (Node.js):**
```js
// Allow geolocation for same origin
res.setHeader('Permissions-Policy', 'geolocation=(self), microphone=(), camera=()');
```

---

### Cross-Origin-Opener-Policy (COOP)

```
Cross-Origin-Opener-Policy: same-origin
```

**Protects against:** Cross-origin window attacks — a malicious popup or opener page accessing your browsing context. Also required to enable certain browser features like `SharedArrayBuffer` (used in high-precision timing attacks like Spectre).

**Browser support:** Chrome 83+, Firefox 79+, Safari 15.2+.

---

### Cross-Origin-Resource-Policy (CORP)

```
Cross-Origin-Resource-Policy: same-origin
```

**Protects against:** Cross-origin reads of your resources by other sites (Spectre-class attacks, data leakage).

Instructs the browser to block no-cors cross-origin requests to your resources. Change to `cross-origin` if you intentionally serve resources as a CDN or public API.

**Browser support:** Chrome 73+, Firefox 74+, Safari 12+.

---

### Cross-Origin-Embedder-Policy (COEP)

```
Cross-Origin-Embedder-Policy: require-corp
```

**Protects against:** Cross-origin data leakage via embedded resources (images, scripts, iframes from third-party origins).

When combined with COOP `same-origin`, enables cross-origin isolation — required for `SharedArrayBuffer` and high-resolution timers. Requires all embedded resources to have CORP or CORS headers. This may break third-party embeds; adjust if needed.

**Browser support:** Chrome 83+, Firefox 79+, Safari 15.2+.

---

### X-Permitted-Cross-Domain-Policies

```
X-Permitted-Cross-Domain-Policies: none
```

**Protects against:** Adobe Flash and PDF cross-domain policy files (`crossdomain.xml`) being used to load your site's data from Flash plugins.

**Browser support:** Flash/PDF specific — not relevant for modern browsers without Flash.

---

### NEL (Network Error Logging)

```
NEL: {"report_to":"default","max_age":31536000,"include_subdomains":true}
```

**Protects against:** Allows the browser to report network errors (failed DNS, TCP connection errors, TLS errors) to a reporting endpoint, helping detect downgrade attacks and connectivity issues.

Note: NEL requires a companion `Report-To` header pointing to a collection endpoint. Without `Report-To`, NEL is defined but no reports are sent.

**Browser support:** Chrome 69+. Limited Firefox/Safari support.

---

### X-Powered-By — removed

```
X-Powered-By: (removed)
```

**Protects against:** Technology fingerprinting — an attacker learning which framework you use to target known vulnerabilities.

Express sets `X-Powered-By: Express` by default. The WAF calls `res.removeHeader('X-Powered-By')` to suppress this.

---

## Customizing headers

**Node.js:** Edit `nodejs/middleware/securityHeaders.js` directly. The middleware is a simple function that calls `res.setHeader()`. Any header set here can be overridden by subsequent middleware.

**PHP:** Edit `php/src/Response.php`. The `sendSecurityHeaders()` method calls `header()` for each directive.

To disable a single header without modifying the WAF source, add a middleware after `createWAF()` that removes it:

```js
app.use(...createWAF());
app.use((req, res, next) => {
  res.removeHeader('Cross-Origin-Embedder-Policy'); // if breaking third-party embeds
  next();
});
```
