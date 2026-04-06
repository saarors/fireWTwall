# Contributing to fireWTwall

Thanks for your interest in contributing. This document explains how the project is structured, what kinds of contributions are welcome, and the process for submitting them.

---

## Table of contents

1. [What to contribute](#what-to-contribute)
2. [Project structure](#project-structure)
3. [Development setup](#development-setup)
4. [Adding a detection rule](#adding-a-detection-rule)
5. [Adding a new detector](#adding-a-new-detector)
6. [Porting changes across runtimes](#porting-changes-across-runtimes)
7. [Testing your changes](#testing-your-changes)
8. [Code style](#code-style)
9. [Submitting a pull request](#submitting-a-pull-request)
10. [Reporting a bug or false positive](#reporting-a-bug-or-false-positive)

---

## What to contribute

**Great contributions:**
- New detection rules for existing attack categories (with a real-world payload that triggered the gap)
- False positive fixes — narrowing a regex that fires on legitimate traffic
- New attack categories that aren't covered yet (open an issue first to discuss)
- Bug fixes in rate limiting, IP filter, or logging
- Documentation improvements and typo fixes

**Please avoid:**
- Adding `console.log` / `var_dump` / debug output to production paths
- Changing default config values without a strong reason
- Breaking the shared log format
- Adding external runtime dependencies — the zero-dependency principle is intentional

---

## Project structure

The three runtimes (Node.js, PHP, ASP.NET) are parallel implementations of the same pipeline. A change to one detector usually needs to be mirrored in all three.

```
fireWTwall/
├── nodejs/middleware/        ← Node.js / Express / Bun detectors
├── php/src/detectors/        ← PHP detector classes
├── aspnet/src/detectors/     ← ASP.NET (C#) detector classes
└── docs/rules/               ← Per-category rule documentation
```

| Runtime | Language | Entry point | Pattern utility |
|---------|----------|-------------|-----------------|
| Node.js | JavaScript | `nodejs/waf.js` → `middleware/index.js` | `utils/patternMatcher.js` |
| PHP | PHP 8.0+ | `php/waf.php` → `WAF.php` | `Request::deepDecode()` |
| ASP.NET | C# / .NET 4.7.2+ | `WafHttpModule.cs` → `WAF.cs` | `WafRequest.DeepDecode()` |

---

## Development setup

### Node.js

```bash
# Install dev dependencies (only Express for the example server)
cd nodejs
npm install

# Run the example server
npm start
# → http://localhost:3000
```

### PHP

PHP has no build step. Point a local Apache/nginx virtual host at `php/example/` with `auto_prepend_file` configured, or use the built-in PHP server:

```bash
cd php/example
php -d auto_prepend_file=../waf.php -S localhost:8080
```

### ASP.NET

Open `aspnet/example/` in Visual Studio or use IIS Express:

```bash
# With .NET SDK installed
cd aspnet/example
dotnet run        # or use Visual Studio / IIS Express
```

---

## Adding a detection rule

Each detector holds a static list of rules. A rule has three fields:

| Field | Purpose |
|-------|---------|
| `name` / `id` | Kebab-case identifier that appears in logs, e.g. `sql-new-rule` |
| `severity` | `critical`, `high`, or `medium` |
| `pattern` | Compiled regex |

### Severity guide

| Severity | Use when |
|----------|----------|
| `critical` | Direct code execution, data exfiltration, or authentication bypass |
| `high` | Strong indicator of active exploitation attempt |
| `medium` | Suspicious but could appear in legitimate traffic; lower confidence |

### Node.js — `nodejs/middleware/<detector>.js`

```js
{ name: 'sql-new-rule', severity: 'high',
  pattern: /\bnew_function\s*\(/i },
```

### PHP — `php/src/detectors/<Detector>Detector.php`

```php
['name' => 'sql-new-rule', 'severity' => 'high',
 'pattern' => '/\bnew_function\s*\(/i'],
```

### ASP.NET — `aspnet/src/detectors/<Detector>Detector.cs`

```csharp
("sql-new-rule", "high",
  new Regex(@"\bnew_function\s*\(", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
```

After adding the rule, update the corresponding `docs/rules/<category>.md` with the new rule name, severity, what it catches, and an example payload.

---

## Adding a new detector

If the attack category doesn't exist yet, you need to:

1. **Create the detector in all three runtimes** (Node.js, PHP, ASP.NET) — see existing detectors as templates.
2. **Wire it into the pipeline** in each runtime's orchestrator:
   - Node.js: `nodejs/middleware/index.js`
   - PHP: `php/src/WAF.php`
   - ASP.NET: `aspnet/src/WAF.cs`
3. **Create a rule doc** at `docs/rules/<category>.md`.
4. **Update the protection table** in `README.md` and `docs/index.md`.
5. **Add test commands** to the README test section.

### Detector contract

Every detector must return either:
- A hit object `{ rule, severity, matched, source }` (Node.js) / `?array` (PHP) / `DetectorResult?` (C#)
- `null` / `null` / `null` if no match

The `matched` string must be truncated to 120 characters. Never throw — return `null` on unexpected input.

---

## Porting changes across runtimes

When you update a regex in one runtime, update it in the other two as well. The three pattern lists should stay in sync.

**Regex translation reference:**

| PHP | Node.js | C# |
|-----|---------|-----|
| `/pattern/i` | `/pattern/i` | `new Regex(@"pattern", RegexOptions.IgnoreCase)` |
| `/pattern/m` | `/pattern/m` | `new Regex(@"pattern", RegexOptions.Multiline)` |
| `/pattern/i` compiled static | same | add `RegexOptions.Compiled` |
| `\b` word boundary | `\b` | `\b` |
| `(?:...)` non-capturing | `(?:...)` | `(?:...)` |

**Key differences to watch:**
- PHP and JS use `/regex/flags` syntax; C# uses `new Regex(@"pattern", options)`.
- In C# verbatim strings (`@"..."`), backslashes do not need to be doubled.
- PHP `preg_match` returns the match in `$m[0]`; Node.js `pattern.exec(s)` returns the match in `m[0]`; C# `Regex.Match(s)` returns a `Match` object — use `m.Value`.

---

## Testing your changes

There is no automated test suite yet. Test manually using `curl`:

```bash
# Start the Node.js example server
cd nodejs && npm start

# Attack vector that should now be blocked (your new rule)
curl -i "http://localhost:3000/?q=<your-payload>"
# Expected: HTTP 403

# Clean request — must still pass
curl -i "http://localhost:3000/"
# Expected: HTTP 200

# Check the log
tail -1 nodejs/logs/waf.log | jq .
# Expected: result "blocked", rule "<your-rule-name>"
```

Also test the PHP version:

```bash
cd php/example
php -d auto_prepend_file=../waf.php -S localhost:8080 &
curl -i "http://localhost:8080/?q=<your-payload>"
```

Before submitting, run through the full set of test vectors in the README to make sure nothing regresses.

---

## Code style

### JavaScript
- `'use strict'` at the top of every file
- `const` and `let` only — no `var`
- 2-space indentation
- Single quotes for strings
- No semicolons at end of lines (existing style)

### PHP
- Strict types: `declare(strict_types=1)` is not required in detectors, but do not weaken existing type signatures
- 4-space indentation
- Follow PSR-12 formatting

### C#
- 4-space indentation
- `var` for local variables where the type is obvious
- `readonly` on static rule arrays
- `RegexOptions.Compiled` on all static regexes

### All runtimes
- Keep the `name`/`id` identical across all three runtimes for the same rule — logs must be consistent
- Truncate `matched` to 120 characters before returning
- No external dependencies

---

## Submitting a pull request

1. **Fork** the repository and create a branch from `main`:
   ```bash
   git checkout -b feat/my-new-rule
   ```

2. **Make your changes** — update all three runtimes if you touched a detector.

3. **Update docs** — add or update the relevant `docs/rules/<category>.md` and any affected README sections.

4. **Test manually** using the curl commands above.

5. **Open a PR** against `main` with:
   - A clear title: `feat(sql): add WAITFOR DELAY variant` or `fix(xss): narrow svg rule false positive`
   - A description that includes:
     - What attack or false positive you're addressing
     - A real-world payload (or sanitised version) that triggered the gap
     - Which runtimes were updated
     - Any known limitations or edge cases

---

## Reporting a bug or false positive

Open an issue at [github.com/saarors/fireWTwall/issues](https://github.com/saarors/fireWTwall/issues) with:

- **For a false positive:** the exact request (URL, headers, body) that was wrongly blocked, the rule name from the log (`X-WAF-Rule` header or `waf.log`), and what the legitimate use case is.
- **For a missed attack:** the payload that was not blocked and the attack category it belongs to.
- **For a bug:** the runtime (Node.js / PHP / ASP.NET), the version, steps to reproduce, and the expected vs actual behaviour.

For security vulnerabilities in the WAF itself, please open a private advisory rather than a public issue.
