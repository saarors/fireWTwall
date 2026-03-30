# LDAP Injection Rules

The WAF applies 6 LDAP injection rules.

**Scanned sources:** query params, request body, cookies.

---

## How LDAP filters work

LDAP (Lightweight Directory Access Protocol) uses a filter syntax to search directory entries:

```
(attribute=value)
(&(uid=alice)(password=secret))
(|(uid=admin)(uid=root))
```

Operators: `&` (AND), `|` (OR), `!` (NOT).
Special characters: `(`, `)`, `*`, `\`, `\0` (null byte).

**Vulnerable code example:**
```php
$filter = "(&(uid=" . $_GET['user'] . ")(password=" . $_GET['pass'] . "))";
$result = ldap_search($ds, $dn, $filter);
```

If `user` is `*)(uid=*))(|(uid=*`, the filter becomes:
```
(&(uid=*)(uid=*))(|(uid=*)(password=anything))
```

This matches all users — authentication is bypassed.

---

## All 6 rules

| Rule ID | Severity | Pattern | Example payload | Description |
|---------|----------|---------|-----------------|-------------|
| `ldap-wildcard-bypass` | high | `*)(attr=*` or bare `*` | `*)(uid=*` | Wildcard used to match all values in a filter attribute |
| `ldap-injection-paren` | critical | `*)(\|` / `*)(\&` | `*)(|(uid=admin)` | OR/AND filter injection — closes current filter and opens a new logical condition |
| `ldap-injection-null` | high | `\x00` / `%00.*uid` / `uid.*%00` | `admin%00` | Null byte truncation in uid searches — may terminate the uid value early |
| `ldap-injection-close` | critical | `*)(uid=*` | `*)(uid=*)` | Closes the uid filter and opens an unconditional wildcard match |
| `ldap-injection-admin` | critical | `*)( cn=admin` / `)(&(password` | `*)(cn=admin)(password=` | Directly injects admin lookup or password filter manipulation |
| `ldap-injection-encode` | high | `*28` / `*29` / `*00` / `*2a` | `admin*28*29` | Hex-encoded LDAP special characters: `(` = `\28`, `)` = `\29`, null = `\00`, `*` = `\2a` |

---

## Filter bypass examples

**Authentication bypass via wildcard:**
```bash
# Intended filter: (&(uid=USER)(password=PASS))
# Injected:        (&(uid=*)(password=anything))  — matches first user
curl "http://localhost:3000/login?user=*&pass=anything"
```

**OR injection — match admin:**
```bash
# Injected filter: (&(uid=*)(|(uid=admin))(password=anything))
curl "http://localhost:3000/login?user=*)(|(uid=admin"
```

**AND injection:**
```bash
curl "http://localhost:3000/search?user=*)(uid=*))(|(uid=*"
```

**Hex-encoded bypass attempt:**
```bash
# Attacker encodes ( as \28 and ) as \29 to bypass string filters
curl "http://localhost:3000/login?user=admin*28password*3d*29"
```

All of these return `403 Forbidden`.

---

## Null byte injection

LDAP directories built on C libraries may be vulnerable to null byte injection. Inserting `\0` (null byte) into a uid search can cause the LDAP library to stop reading the string early, effectively truncating the value:

```
uid=admin\0attacker_suffix
```

Depending on the implementation, this might match `uid=admin` while the application receives `admin\0attacker_suffix` as the username. The `ldap-injection-null` rule detects null bytes adjacent to `uid` in the input.

---

## Wildcard enumeration

Beyond authentication bypass, LDAP wildcard injection allows directory enumeration:

```ldap
(uid=a*)    ← lists all users starting with 'a'
(uid=ab*)   ← narrows to 'ab'
(mail=*)    ← dumps all email addresses
```

The `ldap-wildcard-bypass` rule blocks the patterns commonly used for this technique.
