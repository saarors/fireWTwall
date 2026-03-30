# Deserialization Attack Rules

The WAF applies 7 deserialization rules covering PHP, Java, Python, and Node.js.

**Scanned sources:** query params, request body, cookies, `req.rawBody` (if set by a body parser).

---

## What insecure deserialization is

Deserialization converts a byte stream or string back into a language object. When an application deserializes untrusted user-supplied data, an attacker can craft a malicious serialized object that:

1. Triggers code execution during deserialization (gadget chains)
2. Causes unexpected application state changes
3. Crashes the application (denial of service)

Deserialization vulnerabilities are in OWASP Top 10 (A08:2021).

---

## PHP object injection

PHP's `unserialize()` function reconstructs objects from a serialized string. If a class has a `__wakeup()` or `__destruct()` magic method, it executes when the object is unserialized.

**PHP serialized object format:** `O:<name_length>:"<classname>":<prop_count>:{<properties>}`

| Rule ID | Severity | Pattern | Example payload | Description |
|---------|----------|---------|-----------------|-------------|
| `deser-php-object` | critical | `O:\d+:"[classname]":\d+:{` | `O:8:"stdClass":0:{}` | PHP serialized object — class instantiation triggers magic methods |
| `deser-php-array` | high | `a:\d+:{i:\d+;` or `s:\d+:"` | `a:2:{i:0;s:5:"hello";i:1;s:5:"world";}` | PHP serialized array — less dangerous but indicates serialized data in input |

```bash
# Basic PHP object injection
curl "http://localhost:3000/?data=O:8:\"stdClass\":0:{}"

# Targeting a class with __wakeup
curl "http://localhost:3000/?obj=O:10:\"FileWriter\":1:{s:4:\"path\";s:17:\"/var/www/shell.php\";}"
```

---

## Java deserialization

Java's `ObjectInputStream.readObject()` is vulnerable when it deserializes untrusted data. Java serialized streams begin with the magic bytes `AC ED 00 05`. Gadget chains in libraries like Commons Collections, Spring, and Hibernate allow RCE without requiring a vulnerable custom class.

**Tools:** ysoserial, Gadget Inspector, JexBoss.

| Rule ID | Severity | Pattern | Example payload | Description |
|---------|----------|---------|-----------------|-------------|
| `deser-java-b64` | critical | `rO0AB[XY]` | `rO0ABXNy...` | Base64-encoded Java serialized stream — `AC ED 00 05` encodes to `rO0ABX` in base64 |
| `deser-java-hex` | critical | `aced0005` | `aced0005...` | Hex-encoded Java serialized stream magic bytes |

```bash
# Java deserialization via base64 in a query param
curl "http://localhost:3000/?payload=rO0ABXNyAC5vcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMu"

# Hex magic bytes
curl "http://localhost:3000/?data=aced000573720032..."
```

The base64 prefix `rO0AB` always indicates a Java serialized object. The `X` or `Y` that follows represents the next bytes of the Java object stream header. ysoserial payloads always start with `rO0ABXNy` (stream header + TC_OBJECT + TC_CLASSDESC).

---

## Python pickle

Python's `pickle` module serializes and deserializes Python objects. The `__reduce__` method on a pickled object executes when it is deserialized, allowing arbitrary code execution.

**Protocol headers:**
- Protocol 2: `\x80\x02`
- Protocol 4: `\x80\x04`
- Legacy (protocol 0): `(dp` at start, `cos\nsystem\n` for OS command execution

| Rule ID | Severity | Pattern | Example payload | Description |
|---------|----------|---------|-----------------|-------------|
| `deser-python-pickle` | critical | `\x80[\x01-\x05]` / `(dp\d+\n` / `cos\nsystem\n` | `\x80\x02c__builtin__\nexec\n...` | Raw Python pickle protocol bytes |
| `deser-python-b64pick` | high | `gASV` / `gAJ[TU]` | `gASVAAAAAAAAAAAA...` | Base64-encoded pickle protocol 4 (`gASV`) or protocol 2 (`gAJT` / `gAJU`) |

The `cos\nsystem\n` pattern specifically detects the classic pickle payload that calls `os.system()` for command execution.

---

## node-serialize RCE

The `node-serialize` npm package (abandoned, last published 2017) has a known RCE vulnerability. If a serialized object contains a property whose value is a JavaScript IIFE (Immediately Invoked Function Expression) prefixed with `_$$ND_FUNC$$_`, the function is evaluated with `eval()` when deserialized.

| Rule ID | Severity | Pattern | Example payload | Description |
|---------|----------|---------|-----------------|-------------|
| `deser-node-serialize` | critical | `{"rce":"_$$ND_FUNC$$_function` | `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}` | node-serialize eval gadget |

```bash
curl -X POST http://localhost:3000/api \
  -H "Content-Type: application/json" \
  -d '{"rce":"_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"id\",console.log)}()"}'
```

---

## rawBody scanning

The deserialization middleware also inspects `req.rawBody` if it is set by a body parser that preserves the raw request body string. This is important for detecting binary-format payloads (Java `aced0005`, Python pickle bytes) that may be lost when a JSON or URL-encoded body parser processes the request.

To enable raw body access in Express:

```js
app.use(express.raw({ type: '*/*', limit: '10mb' }));
// or use a custom middleware that sets req.rawBody
```
