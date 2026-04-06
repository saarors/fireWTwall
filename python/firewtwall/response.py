from __future__ import annotations
import json
import html as html_mod
from typing import List, Tuple

SECURITY_HEADERS = [
    ("X-Content-Type-Options",            "nosniff"),
    ("X-Frame-Options",                   "SAMEORIGIN"),
    ("X-XSS-Protection",                  "1; mode=block"),
    ("Referrer-Policy",                   "strict-origin-when-cross-origin"),
    ("Cross-Origin-Opener-Policy",        "same-origin"),
    ("Cross-Origin-Resource-Policy",      "same-origin"),
    ("Cache-Control",                     "no-store"),
    ("Strict-Transport-Security",         "max-age=31536000; includeSubDomains; preload"),
    ("Content-Security-Policy",
     "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"),
    ("X-Permitted-Cross-Domain-Policies", "none"),
]


def _build_headers(extra: List[Tuple[str, str]] = None) -> List[Tuple[str, str]]:
    headers = list(SECURITY_HEADERS)
    if extra:
        headers.extend(extra)
    return headers


def block_wsgi(rule: str, status: int = 403,
               response_type: str = "json") -> Tuple[str, List[Tuple[str, str]], bytes]:
    """Return (status_line, headers, body) for a WSGI response."""
    status_line = f"{status} Blocked"
    body = _build_body(rule, response_type)
    ct = "application/json; charset=utf-8" if response_type == "json" else "text/html; charset=utf-8"
    headers = _build_headers([("Content-Type", ct)])
    return status_line, headers, body.encode("utf-8")


def too_many_requests_wsgi(retry_after: int,
                           response_type: str = "json") -> Tuple[str, List[Tuple[str, str]], bytes]:
    body = json.dumps({
        "blocked": True, "rule": "rate-limit",
        "message": "Too many requests", "retryAfter": retry_after,
    }) if response_type == "json" else f"<h1>429 Too Many Requests</h1><p>Retry after {retry_after}s.</p>"
    ct = "application/json; charset=utf-8" if response_type == "json" else "text/html; charset=utf-8"
    headers = _build_headers([("Content-Type", ct), ("Retry-After", str(retry_after))])
    return "429 Too Many Requests", headers, body.encode("utf-8")


def _build_body(rule: str, response_type: str) -> str:
    if response_type == "json":
        return json.dumps({"blocked": True, "rule": rule, "message": "Request blocked by WAF"})
    safe_rule = html_mod.escape(rule)
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>403 Blocked</title>
<style>
body{{font-family:sans-serif;display:flex;align-items:center;justify-content:center;
     height:100vh;margin:0;background:#f4f4f4}}
.box{{text-align:center;padding:2rem;background:#fff;border-radius:8px;
     box-shadow:0 2px 8px rgba(0,0,0,.1)}}
h1{{color:#c0392b}}code{{background:#eee;padding:2px 6px;border-radius:3px}}
</style></head>
<body><div class="box">
<h1>&#x1F6AB; Access Blocked</h1>
<p>Your request was blocked by the web application firewall.</p>
<p>Rule: <code>{safe_rule}</code></p>
</div></body></html>"""
