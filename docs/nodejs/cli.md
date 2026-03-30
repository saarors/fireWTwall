# waf-log CLI Reference

The `waf-log` binary is included in the npm package. Run it with `npx waf-log` or `./node_modules/.bin/waf-log`.

---

## Synopsis

```
waf-log [options] [logfile]
```

The default log file is `./logs/waf.log` relative to the current working directory. Pass a path as the last positional argument to use a different file.

---

## All flags

| Flag | Argument | Description |
|------|----------|-------------|
| `--tail` | `N` | Show last N entries (default: 50) |
| `--stats` | — | Show summary statistics instead of entries |
| `--blocked` | — | Show only entries with `result: "blocked"` |
| `--passed` | — | Show only entries with `result: "passed"` (requires debug mode) |
| `--ip` | `ADDR` | Filter by exact IP address |
| `--rule` | `NAME` | Filter by rule name (partial match) |
| `--since` | `ISO date` | Show only entries after this timestamp |
| `--json` | — | Raw NDJSON output (no color, no formatting) |
| `--help` | — | Print usage and exit |

---

## Examples

### Default — last 50 entries

```bash
npx waf-log
```

Output (colored in a TTY):
```
── fireWTwall log (last 50 of 1234 filtered) ──
2026-03-30T10:00:01Z a1b2c3d4 blocked GET    203.0.113.42    /search → sql-union-select [query] matched:"UNION SELECT" critical 0.83ms
2026-03-30T10:00:05Z b2c3d4e5 blocked GET    45.33.32.156    /login  → bot [user-agent] matched:"sqlmap/1.7" 0.12ms
```

---

### Show last 100 entries from a custom log file

```bash
npx waf-log --tail 100 /var/log/waf.log
```

---

### Stats — top rules, top IPs, severity breakdown

```bash
npx waf-log --stats
```

Output:
```
── fireWTwall log stats ──────────────────────────────
  Total entries : 1234
  Blocked       : 1187
  Passed        : 47
  From          : 2026-03-29T00:00:00Z
  To            : 2026-03-30T10:00:01Z

  Top rules:
      342  sql-union-select
      201  bot
       88  xss-script-tag
       54  path-traversal-dotdot
       31  log4shell-jndi

  Top offending IPs:
      487  203.0.113.42
      201  45.33.32.156
       99  198.20.70.114

  Severity breakdown:
    critical : 892
    high     : 241
    medium   : 54
```

---

### Only blocked requests

```bash
npx waf-log --blocked
```

---

### Only passed requests (debug mode logs)

```bash
npx waf-log --passed
```

---

### Filter by IP

```bash
npx waf-log --ip 203.0.113.42
```

---

### Filter by rule name (partial match)

```bash
# All SQL injection rules
npx waf-log --rule sql

# Only Log4Shell
npx waf-log --rule log4shell

# Only the union-select rule specifically
npx waf-log --rule sql-union-select
```

---

### Filter by timestamp

```bash
# Everything since midnight UTC
npx waf-log --since 2026-03-30T00:00:00Z

# Combine with other filters
npx waf-log --blocked --since 2026-03-30T00:00:00Z --rule sql
```

---

### Raw NDJSON — pipe-friendly

```bash
# Raw output
npx waf-log --json

# Pipe to jq for custom filtering
npx waf-log --json | jq 'select(.severity == "critical")'

# Get all unique IPs that triggered SQL injection rules
npx waf-log --json | jq -r 'select(.rule | startswith("sql")) | .ip' | sort -u

# Count blocks per rule in the last hour
npx waf-log --since 2026-03-30T09:00:00Z --json | \
  jq -r '.rule // "unknown"' | sort | uniq -c | sort -rn

# Export blocked entries as CSV
npx waf-log --blocked --json | \
  jq -r '[.timestamp, .ip, .rule, .path] | @csv'
```

---

### Watch mode — live tail

```bash
# Refresh every 2 seconds, show last 20 blocked
watch -n 2 'npx waf-log --tail 20 --blocked'
```

On Windows (PowerShell):
```powershell
while ($true) { npx waf-log --tail 20 --blocked; Start-Sleep 2; Clear-Host }
```

---

## Color output

The CLI uses ANSI colors in TTY mode:

| Color | Meaning |
|-------|---------|
| Red | `blocked` result, `critical` severity |
| Yellow | Rule name, `high` severity |
| Cyan | `medium` severity |
| Green | `passed` result |
| Magenta | IP address |
| Grey | Timestamp, request ID, matched value |

Set `NO_COLOR=1` in your environment to disable colors (e.g. when piping to a file).

```bash
NO_COLOR=1 npx waf-log --stats > report.txt
```
