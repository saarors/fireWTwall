# Open Redirect Rule

The WAF applies 1 open redirect rule.

**Scanned sources:** Query params and body fields with redirect-suggestive names.

---

## What open redirect is

An open redirect vulnerability allows an attacker to craft a URL to a trusted site that redirects users to an arbitrary external destination. Attackers use this in phishing attacks: the URL displays a trusted domain in the browser status bar and address bar before the redirect occurs.

Example:
```
https://trusted-bank.com/login?returnUrl=https://evil-bank.com/login
```

The user sees `trusted-bank.com` in the link, clicks it, and is redirected to `evil-bank.com` which displays a fake login page.

---

## Which parameter names trigger the check

The WAF checks values in params with these names (case-insensitive):

| Query param / body field names |
|-------------------------------|
| `redirect`, `return`, `next`, `dest`, `destination`, `url`, `callback`, `goto`, `returnUrl`, `returnTo`, `continue`, `forward`, `location`, `target`, `to` |

---

## Detection logic

The rule blocks values that:

1. Start with `http://` or `https://` (absolute URL to an external site)
2. Start with `//` (protocol-relative URL — resolves to `http://` or `https://` based on the current page protocol)

Relative URLs like `/dashboard` or `/profile?tab=settings` are allowed.

---

## Example payloads

**Absolute URL redirect:**
```bash
# Should return 403
curl -i "http://localhost:3000/login?returnUrl=https://evil.com"
curl -i "http://localhost:3000/logout?redirect=http://phishing.site/login"
```

**Protocol-relative redirect:**
```bash
# Should return 403
curl -i "http://localhost:3000/login?next=//evil.com/fake-login"
curl -i "http://localhost:3000/?return=//attacker.com"
```

**Legitimate redirect — allowed:**
```bash
# Relative URL — should return 200
curl -i "http://localhost:3000/login?next=/dashboard"
curl -i "http://localhost:3000/checkout?return=/cart"
```

---

## Log entry

```json
{
  "rule": "open-redirect",
  "matched": "https://evil.com",
  "source": "query:returnUrl",
  "severity": "medium"
}
```

The `source` field shows which parameter carried the payload.

---

## Bypasses this rule covers

Some open redirect filters only check for `http://` and miss:

- `//evil.com` — protocol-relative URL (detected by `//` prefix check)
- `https://evil.com` — HTTPS variant (detected by `https://` check)

The rule does not try to validate the domain name because domain-validation approaches (allowlists, regex domain matching) are error-prone and prone to bypass via subdomain abuse (`yoursite.com.evil.com`). The safest approach — enforced here — is to reject any value starting with a URL protocol or `//`.

---

## Complementary measure

The WAF rule prevents the malicious URL from reaching your application code. For defense-in-depth, your application should also:

1. Validate that the redirect destination matches an allowlist of your own domains.
2. Prefer opaque token-based redirects (store the destination server-side, map to a short token in the URL).
