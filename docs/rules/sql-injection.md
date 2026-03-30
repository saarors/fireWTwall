# SQL Injection Rules

The WAF applies 38 SQL injection rules. Rules are evaluated in order; the first match blocks the request.

**Scanned sources:** query params, request body, URL path, cookies.

---

## Critical severity

### UNION-based injection

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `sql-union-select` | `UNION [ALL] SELECT` | `1 UNION SELECT username,password FROM users` | Retrieves data from arbitrary tables by appending a second SELECT |
| `sql-information-schema` | `information_schema` | `1 UNION SELECT table_name FROM information_schema.tables` | Enumerates all database tables and column names |
| `sql-sys-schema` | `sys.(user_summary\|processlist\|statements_with_errors)` | `1 UNION SELECT * FROM sys.user_summary` | MySQL sys schema exposes user credentials and query statistics |

```bash
curl "http://localhost:3000/?id=1+UNION+SELECT+username,password+FROM+users--"
```

---

### Stacked / destructive queries

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `sql-drop-table` | `; DROP TABLE` | `1; DROP TABLE users--` | Destroys database tables |
| `sql-stacked-query` | `; SELECT/INSERT/UPDATE/DELETE/...` | `1; INSERT INTO admins VALUES('x','x')` | Executes a second arbitrary SQL statement |
| `sql-bulk-insert` | `BULK INSERT` | `'; BULK INSERT users FROM '\\attacker\share\data.csv'` | MSSQL bulk load from an attacker-controlled file |
| `sql-openrowset` | `OPENROWSET(` | `'; SELECT * FROM OPENROWSET('SQLOLEDB','...')` | MSSQL linked-server data exfiltration |

---

### Time-based blind injection

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `sql-sleep` | `SLEEP(\d` | `1 AND SLEEP(5)` | MySQL: delays response to confirm injection point |
| `sql-benchmark` | `BENCHMARK(` | `1 AND BENCHMARK(10000000,MD5('x'))` | MySQL: CPU-based delay without SLEEP |
| `sql-waitfor-delay` | `WAITFOR DELAY` | `1; WAITFOR DELAY '0:0:5'` | MSSQL time-based blind injection |
| `sql-pg-sleep` | `pg_sleep(` | `1 AND pg_sleep(5)` | PostgreSQL time-based blind injection |

---

### File read/write

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `sql-load-file` | `LOAD_FILE(` | `1 UNION SELECT LOAD_FILE('/etc/passwd')` | MySQL reads arbitrary files from the server filesystem |
| `sql-into-outfile` | `INTO OUTFILE/DUMPFILE` | `1 UNION SELECT '<?php system($_GET[c])?>' INTO OUTFILE '/var/www/shell.php'` | MySQL writes a web shell to disk |

```bash
curl "http://localhost:3000/?id=1+UNION+SELECT+LOAD_FILE('/etc/passwd')--"
```

---

### MSSQL-specific RCE

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `sql-xp-cmdshell` | `xp_cmdshell` | `'; EXEC xp_cmdshell 'whoami'--` | MSSQL stored procedure that executes OS commands |
| `sql-exec` | `EXEC(` / `EXECUTE(` | `'; EXEC('xp_cmdshell ''whoami''')` | MSSQL dynamic SQL execution |

---

### Error-based injection (v2 rules)

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `sql-extractvalue` | `EXTRACTVALUE(` | `EXTRACTVALUE(1,CONCAT(0x7e,version()))` | MySQL: leaks data via XML parse error message |
| `sql-updatexml` | `UPDATEXML(` | `UPDATEXML(1,CONCAT(0x7e,user()),1)` | MySQL: leaks data via XML update error |
| `sql-gtid` | `GTID_SUBSET(` | `GTID_SUBSET(concat(0x7e,version()),1)` | MySQL: error-based data exfiltration |
| `sql-exp-tilde` | `exp(~(` | `exp(~(select*from(select version())x))` | MySQL: double-negation overflow error injection |
| `sql-polygon` | `polygon(/geometrycollection/linestring/multipoint)(` | `geometrycollection((select*from(select version())a))` | MySQL geometry function error injection |
| `sql-procedure-analyse` | `PROCEDURE ANALYSE(` | `1 UNION SELECT 1 PROCEDURE ANALYSE(1,1)` | MySQL: exposes column data types via error |

---

### DBMS fingerprinting

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `sql-dbms-fingerprint` | `@@version` / `version()` / `user()` / `database()` | `1 AND @@version>0` | Reveals DBMS version and user for targeted exploitation |
| `sql-dbms-version` | `@@version` / `@@global` / `@@session` | `1 UNION SELECT @@global.version_compile_os` | Reveals OS and session configuration |
| `sql-sys-tables` | `sysobjects` / `syscolumns` | `1 UNION SELECT name FROM sysobjects WHERE xtype='U'` | MSSQL: enumerates all user tables |

---

## High severity

### Comment injection

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `sql-comment` | `--` / `/*` / `*/` / `# (end of line)` | `' OR 1=1--` | SQL comments terminate WHERE clauses to bypass authentication |

---

### Type conversion

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `sql-cast-convert` | `CAST(` / `CONVERT(` | `CAST((SELECT password FROM users) AS int)` | Error-based injection using failed type casts |
| `sql-char-concat` | `CHAR(\d` | `CHAR(65)+CHAR(78)+CHAR(68)` | Constructs SQL keywords character-by-character to evade string filters |

---

### MSSQL / TSQL specific

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `sql-declare-set` | `DECLARE @var` | `'; DECLARE @q varchar(1000); SET @q='SELECT ...'` | MSSQL dynamic SQL construction in variables |
| `sql-rowterminator` | `ROWTERMINATOR` | `BULK INSERT ... ROWTERMINATOR = '0x0a'` | MSSQL: controls row delimiter in bulk operations |
| `sql-case-when` | `CASE WHEN ... THEN` | `1 AND CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END` | Conditional injection for blind boolean-based extraction |
| `sql-having` | `HAVING \d=\d` | `1 HAVING 1=1` | Group-by tautology to expose column names via error |

---

### Geometry functions

| Rule ID | Pattern |
|---------|---------|
| `sql-polygon` | `polygon`, `geometrycollection`, `linestring`, `multipoint` |

---

## Medium severity

### Boolean tautologies

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `sql-boolean-true` | `OR '1'='1'` / `OR 1=1` | `' OR '1'='1` | Bypasses WHERE clause — returns all rows |
| `sql-boolean-and` | `AND '1'='1'` | `' AND '1'='1` | Confirms injection without changing query result |
| `sql-tautology` | `' OR 'x'='x` | `admin' OR 'x'='x` | Classic authentication bypass |
| `sql-order-by-num` | `ORDER BY \d` | `1 ORDER BY 3` | Used to count columns for UNION-based injection |

---

### Obfuscation techniques

| Rule ID | Pattern | Example payload | Why dangerous |
|---------|---------|-----------------|---------------|
| `sql-hex-values` | `0x[0-9a-f]{4+}` | `SELECT 0x414243` | Encodes strings as hex to bypass string-based filters |
| `sql-group-by-having` | `HAVING \d=\d` | `SELECT 1 HAVING 1=1` | Error-based column enumeration |
| `sql-json-extract` | `JSON_EXTRACT(` | `JSON_EXTRACT(password, '$')` | MySQL JSON operator injection |
