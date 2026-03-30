# NoSQL Injection Rules

The WAF applies 11 NoSQL injection rules targeting MongoDB operator injection.

**Scanned sources:** Raw query string (before qs parsing), `req.query`, `req.body`.

---

## How MongoDB operator injection works

MongoDB queries use JSON operators like `$ne`, `$gt`, and `$where` to express conditions. When user input is embedded directly into a query object without sanitization, an attacker can inject these operators to alter query logic.

**Vulnerable Node.js code:**
```js
// Attacker sends: POST /login with body {"username": {"$ne": null}, "password": {"$ne": null}}
const user = await db.collection('users').findOne({
  username: req.body.username,  // {"$ne": null} injected
  password: req.body.password,  // {"$ne": null} injected
});
// findOne({username: {$ne: null}, password: {$ne: null}})
// Returns the first user in the collection — authentication bypassed
```

---

## URL bracket notation

Express and many HTTP parsers interpret `?user[$ne]=1` as `{ user: { '$ne': '1' } }` in `req.query`. The WAF checks both the raw query string (before parsing) and the parsed object.

**Raw query string attack:**
```
/login?user[$ne]=x&pass[$ne]=x
```

After `qs` parsing: `{ user: { '$ne': 'x' }, pass: { '$ne': 'x' } }`

The `scanRawQuery()` function specifically detects the `[$operator]` bracket-notation pattern before it is parsed, providing an additional detection layer.

---

## All 11 rules

### Comparison operators (high)

| Rule ID | Pattern | Example payload | Description |
|---------|---------|-----------------|-------------|
| `nosql-operator-ne` | `[$ne]` / `"$ne":` | `?user[$ne]=x` or `{"user":{"$ne":null}}` | Not-equal — bypass auth by matching any non-null value |
| `nosql-operator-gt` | `[$gt]` / `"$gt":` | `?age[$gt]=0` | Greater-than — enumerate records with numeric fields |
| `nosql-operator-lt` | `[$lt]` / `"$lt":` | `?price[$lt]=99999` | Less-than — enumerate records |
| `nosql-operator-gte` | `[$gte]` / `"$gte":` | `?age[$gte]=0` | Greater-than-or-equal |
| `nosql-operator-lte` | `[$lte]` / `"$lte":` | `?age[$lte]=999` | Less-than-or-equal |
| `nosql-operator-regex` | `[$regex]` / `"$regex":` | `?pass[$regex]=^adm` | Regex matching — used for blind character-by-character extraction |

```bash
# URL bracket notation
curl "http://localhost:3000/login?user[\$ne]=x&pass[\$ne]=x"

# JSON body
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"user": {"$ne": null}, "pass": {"$ne": null}}'
```

---

### JavaScript injection (critical)

| Rule ID | Pattern | Example payload | Description |
|---------|---------|-----------------|-------------|
| `nosql-operator-where` | `"$where":` | `{"$where": "this.username == 'admin'"}` | `$where` executes arbitrary JavaScript on the MongoDB server |
| `nosql-func-sleep` | `"$where": "...sleep(` | `{"$where": "sleep(5000)"}` | Blind injection — confirms vulnerability via time delay |

`$where` is particularly dangerous because it evaluates a JavaScript function in the MongoDB engine (SpiderMonkey in older versions). It was deprecated in MongoDB 4.4 but remains in many production deployments.

```bash
# $where blind injection
curl -X POST http://localhost:3000/api \
  -H "Content-Type: application/json" \
  -d '{"query": {"$where": "sleep(5000)"}}'
```

---

### Aggregation and logical operators (medium)

| Rule ID | Pattern | Example payload | Description |
|---------|---------|-----------------|-------------|
| `nosql-operator-in` | `"$in": [` | `{"status": {"$in": ["admin", "root"]}}` | Matches any value in an array — bypasses single-value checks |
| `nosql-operator-or` | `"$or": [` | `{"$or": [{"user": "admin"}, {"user": "root"}]}` | Logical OR — matches multiple conditions |
| `nosql-operator-expr` | `"$expr":` | `{"$expr": {"$gt": ["$balance", 1000]}}` | Aggregation expression in find queries — can reference other fields |

---

## Blind regex extraction

`$regex` can be used for character-by-character blind extraction of fields:

```bash
# Check if password starts with 'a'
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"user": "admin", "pass": {"$regex": "^a"}}'

# If response differs from a non-match, 'a' is confirmed
```

The WAF blocks the `$regex` operator in requests, preventing this technique.

---

## Common MongoDB versions affected

All MongoDB versions support the `$ne`, `$gt`, `$regex`, `$in`, `$or`, and `$expr` operators. `$where` requires the query engine to support JavaScript execution (available in MongoDB through 4.x; limited in 5.0+). The vulnerability is in application code that passes unsanitized user input to the query, not in MongoDB itself.
