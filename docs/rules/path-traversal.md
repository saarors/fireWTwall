# Path Traversal Rules

The WAF applies 18 path traversal rules.

**Scanned sources:** URL path (`req.originalUrl`), query params, request body.

---

## Dotdot sequences (critical)

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `path-traversal-dotdot` | `../` or `\..` or `/..\` | `../../etc/passwd` | Classic directory traversal — escapes the web root |
| `path-traversal-encoded` | `%2e%2e[%2f%5c]` | `%2e%2e%2fetc%2fpasswd` | URL-encoded `../` — bypasses naive string-based filters |
| `path-traversal-unicode` | `%c0%ae` / `%c1%9c` | `%c0%ae%c0%ae/etc/passwd` | Overlong UTF-8 encoding of `.` and `/` — bypasses UTF-8 validation |
| `path-null-byte` | `%00` / `\x00` | `../../etc/passwd%00.jpg` | Null byte truncates the filename in C-based file APIs, removing any extension check |

```bash
curl "http://localhost:3000/?file=../../etc/passwd"
curl "http://localhost:3000/?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"
curl "http://localhost:3000/?file=../../etc/passwd%00.jpg"
```

---

## Sensitive Unix files (critical)

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `path-etc-passwd` | `/etc/passwd`, `/etc/shadow`, `/etc/hosts`, `/etc/group` | `/etc/passwd` | Contains user account information and password hashes |
| `path-proc-self` | `/proc/self/` | `/proc/self/environ` | Exposes process environment variables including secrets; also used for log poisoning |
| `path-boot` | `/boot/grub`, `/boot/vmlinuz`, `/boot/initrd` | `/boot/grub/grub.cfg` | Boot configuration and kernel image exfiltration |

```bash
curl "http://localhost:3000/?file=/etc/passwd"
curl "http://localhost:3000/?file=/proc/self/environ"
```

---

## Windows paths (critical)

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `path-win-system` | `c:` / `%systemroot%` | `c:\windows\system32\config\SAM` | Windows drive-absolute path — escapes web root on Windows servers |
| `path-system32` | `windows\system32` | `..\..\windows\system32\cmd.exe` | Direct access to Windows system executables |

```bash
curl "http://localhost:3000/?file=c:\windows\system32\config\SAM"
```

---

## Application configuration files (high)

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `path-env-file` | `/.env` (at start or after `/`) | `../../../../.env` | Environment files contain API keys, DB credentials, and secrets |
| `path-wp-config` | `wp-config.php` | `../wp-config.php` | WordPress database credentials in plaintext |
| `path-htaccess` | `.htaccess` | `../.htaccess` | Apache configuration — may contain auth credentials or rewrite rules |
| `path-git-config` | `.git/` | `../.git/config` | Git repository metadata — can expose remote URLs with embedded credentials |
| `path-ssh-keys` | `.ssh/` | `../../.ssh/id_rsa` | SSH private keys |

```bash
curl "http://localhost:3000/?file=../../../../.env"
curl "http://localhost:3000/?file=../../.git/config"
curl "http://localhost:3000/?file=../../.ssh/id_rsa"
```

---

## PHP stream wrappers (high)

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `path-php-wrappers` | `php://`, `zip://`, `phar://`, `data://`, `expect://`, `glob://`, `file://` | `php://input` | PHP stream wrappers can read arbitrary files, execute code, or access process stdin |
| `path-php-filter` | `php://filter`, `php://input`, `php://stdin` | `php://filter/convert.base64-encode/resource=/etc/passwd` | PHP filter wrapper reads and transforms files; base64-encoding bypasses content filters |

```bash
curl "http://localhost:3000/?file=php://filter/convert.base64-encode/resource=/etc/passwd"
curl "http://localhost:3000/?file=phar://shell.phar/test.php"
```

---

## Windows URI scheme (high — v2)

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `path-windows-root` | `[A-Z]:\` / `%SYSTEMROOT%` / `%WINDIR%` | `C:\Users\Administrator\Desktop\secret.txt` | Windows-style absolute path traversal |
| `path-file-scheme` | `file:///[a-zA-Z]:` | `file:///C:/Windows/System32/config/SAM` | Windows file URI — reads local files via SSRF or browser navigation |

```bash
curl "http://localhost:3000/?url=file:///C:/Windows/System32/config/SAM"
```
