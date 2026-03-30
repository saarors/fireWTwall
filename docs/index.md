# fireWTwall Documentation

A production-ready Web Application Firewall with zero external runtime dependencies. Available as an npm package for Node.js/Express and as a drop-in PHP auto-prepend file. Both versions share the same rule sets, detection philosophy, and NDJSON log format.

---

## Documentation index

| File | Description |
|------|-------------|
| [getting-started.md](getting-started.md) | Fast path for Node.js and PHP — install, minimal setup, first test |
| [architecture.md](architecture.md) | Request lifecycle, pattern matching internals, logging, rate limiting |
| [log-format.md](log-format.md) | Complete NDJSON log field reference with examples and jq queries |
| [security-headers.md](security-headers.md) | Every security header added to every response, with customization notes |
| [false-positives.md](false-positives.md) | How to diagnose and resolve false positives |
| [changelog.md](changelog.md) | Version history |

### Node.js

| File | Description |
|------|-------------|
| [nodejs/installation.md](nodejs/installation.md) | Full install guide: requirements, setup, body parser ordering |
| [nodejs/configuration.md](nodejs/configuration.md) | Every config key documented with type, default, and examples |
| [nodejs/middleware-pipeline.md](nodejs/middleware-pipeline.md) | All 23 middleware in order: what each does, HTTP status, severity |
| [nodejs/debug-mode.md](nodejs/debug-mode.md) | Debug mode: headers, log verbosity, CLI usage, production warning |
| [nodejs/cli.md](nodejs/cli.md) | waf-log CLI reference: all flags, example output, jq integration |
| [nodejs/redis.md](nodejs/redis.md) | Redis / multi-process rate limiting: setStore() API and full examples |
| [nodejs/typescript.md](nodejs/typescript.md) | TypeScript usage: all exported types and annotated example |

### PHP

| File | Description |
|------|-------------|
| [php/installation.md](php/installation.md) | Full install guide: all four install options, log directory protection |
| [php/configuration.md](php/configuration.md) | Every waf.config.php key documented with examples |
| [php/rate-limiter.md](php/rate-limiter.md) | APCu vs file-based rate limiting: how each works, setup, shared hosting |
| [php/debug-mode.md](php/debug-mode.md) | PHP debug mode: headers, log verbosity, production warning |

### Detection rules

| File | Description |
|------|-------------|
| [rules/sql-injection.md](rules/sql-injection.md) | 38 SQL injection rules grouped by technique |
| [rules/xss.md](rules/xss.md) | 29 XSS rules grouped by vector type |
| [rules/path-traversal.md](rules/path-traversal.md) | 18 path traversal rules: dotdot, encodings, sensitive files |
| [rules/command-injection.md](rules/command-injection.md) | 18 command injection rules: shells, interpreters, network tools |
| [rules/ssti.md](rules/ssti.md) | 18 SSTI rules covering 9 template engines with CVEs |
| [rules/log4shell.md](rules/log4shell.md) | Log4Shell deep-dive: CVE-2021-44228, JNDI internals, obfuscation variants |
| [rules/shellshock.md](rules/shellshock.md) | Shellshock deep-dive: CVE-2014-6271/7169 and header scanning |
| [rules/nosql-injection.md](rules/nosql-injection.md) | 11 NoSQL injection rules: MongoDB operators, bracket notation, blind injection |
| [rules/ldap-injection.md](rules/ldap-injection.md) | 6 LDAP injection rules: filter bypass, wildcards, null byte |
| [rules/deserialization.md](rules/deserialization.md) | 7 deserialization rules: PHP, Java, Python pickle, node-serialize |
| [rules/ssrf.md](rules/ssrf.md) | SSRF rules: private IPs, cloud metadata, dangerous URI schemes |
| [rules/xxe.md](rules/xxe.md) | XXE rules: DOCTYPE, ENTITY, XInclude — XML bodies only |
| [rules/open-redirect.md](rules/open-redirect.md) | Open redirect rule: which params trigger it, detection logic |
| [rules/rfi.md](rules/rfi.md) | 6 RFI rules: HTTP/FTP/SMB/expect, log poisoning, file param names |
