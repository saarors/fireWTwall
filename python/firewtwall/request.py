from __future__ import annotations
import re
import urllib.parse
import html
from typing import Dict, Optional


_UNICODE_ESC = re.compile(r'\\u([0-9a-fA-F]{4})')


def deep_decode(value: str, max_passes: int = 3) -> str:
    """
    URL-decodes up to max_passes times, strips null bytes, and decodes HTML entities.
    Mirrors PHP Request::deepDecode() and Node.js patternMatcher.deepDecode().
    """
    if not isinstance(value, str):
        return str(value)

    # Normalise double-encoded percent signs (%2500 → %00)
    value = value.replace("%2500", "%00")

    # Decode Unicode escape sequences (\uXXXX → char)
    value = _UNICODE_ESC.sub(lambda m: chr(int(m.group(1), 16)), value)

    prev = None
    for _ in range(max_passes):
        value = value.replace("\x00", "")
        decoded = urllib.parse.unquote_plus(value)
        if decoded == prev:
            break
        prev = value
        value = decoded

    return html.unescape(value)


class WafRequest:
    """
    Framework-agnostic request abstraction.
    Constructed from a WSGI environ dict.
    """

    def __init__(self, environ: dict):
        self._environ = environ
        self.method: str = environ.get("REQUEST_METHOD", "GET").upper()
        self.path: str = environ.get("PATH_INFO", "/")
        self.user_agent: str = environ.get("HTTP_USER_AGENT", "")
        self.content_length: int = self._parse_content_length()
        self.ip: str = self._resolve_ip([])  # resolved later with trusted_proxies
        self._query: Optional[Dict[str, str]] = None
        self._form: Optional[Dict[str, str]] = None
        self._cookies: Optional[Dict[str, str]] = None
        self._headers: Optional[Dict[str, str]] = None
        self._raw_body: Optional[str] = None

    def resolve_ip(self, trusted_proxies: list) -> None:
        self.ip = self._resolve_ip(trusted_proxies)

    # ------------------------------------------------------------------ #
    # Properties
    # ------------------------------------------------------------------ #

    @property
    def query(self) -> Dict[str, str]:
        if self._query is None:
            qs = self._environ.get("QUERY_STRING", "")
            self._query = {
                k: deep_decode(v[-1] if v else "")
                for k, v in urllib.parse.parse_qs(qs, keep_blank_values=True).items()
            }
        return self._query

    @property
    def form(self) -> Dict[str, str]:
        if self._form is None:
            ct = self._environ.get("CONTENT_TYPE", "")
            if "application/x-www-form-urlencoded" in ct or "multipart/form-data" in ct:
                try:
                    body = self.raw_body
                    self._form = {
                        k: deep_decode(v[-1] if v else "")
                        for k, v in urllib.parse.parse_qs(body, keep_blank_values=True).items()
                    }
                except Exception:
                    self._form = {}
            else:
                self._form = {}
        return self._form

    @property
    def cookies(self) -> Dict[str, str]:
        if self._cookies is None:
            raw = self._environ.get("HTTP_COOKIE", "")
            self._cookies = {}
            for part in raw.split(";"):
                if "=" in part:
                    k, _, v = part.strip().partition("=")
                    self._cookies[k.strip()] = deep_decode(v.strip())
        return self._cookies

    @property
    def headers(self) -> Dict[str, str]:
        if self._headers is None:
            self._headers = {}
            for key, value in self._environ.items():
                if key.startswith("HTTP_"):
                    name = key[5:].lower().replace("_", "-")
                    self._headers[name] = value
            if "CONTENT_TYPE" in self._environ:
                self._headers["content-type"] = self._environ["CONTENT_TYPE"]
            if "CONTENT_LENGTH" in self._environ:
                self._headers["content-length"] = self._environ["CONTENT_LENGTH"]
        return self._headers

    @property
    def raw_body(self) -> str:
        if self._raw_body is None:
            try:
                length = self.content_length
                wsgi_input = self._environ.get("wsgi.input")
                if wsgi_input and length > 0:
                    data = wsgi_input.read(length)
                    wsgi_input.seek(0) if hasattr(wsgi_input, "seek") else None
                    self._raw_body = data.decode("utf-8", errors="replace")
                else:
                    self._raw_body = ""
            except Exception:
                self._raw_body = ""
        return self._raw_body

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _parse_content_length(self) -> int:
        try:
            return int(self._environ.get("CONTENT_LENGTH") or 0)
        except (ValueError, TypeError):
            return 0

    def _resolve_ip(self, trusted_proxies: list) -> str:
        from .ip_filter import ip_in_list
        remote = self._environ.get("REMOTE_ADDR", "0.0.0.0")
        if not trusted_proxies:
            return remote
        if not ip_in_list(remote, trusted_proxies):
            return remote
        xff = self._environ.get("HTTP_X_FORWARDED_FOR", "")
        if not xff:
            return remote
        candidates = [c.strip() for c in reversed(xff.split(","))]
        for candidate in candidates:
            try:
                import ipaddress
                ipaddress.ip_address(candidate)
                if not ip_in_list(candidate, trusted_proxies):
                    return candidate
            except ValueError:
                continue
        return remote


class DjangoWafRequest(WafRequest):
    """Thin adapter over a Django HttpRequest."""

    def __init__(self, django_request):
        self._django = django_request
        self.method = django_request.method.upper()
        self.path = django_request.path
        self.user_agent = django_request.META.get("HTTP_USER_AGENT", "")
        try:
            self.content_length = int(django_request.META.get("CONTENT_LENGTH") or 0)
        except (ValueError, TypeError):
            self.content_length = 0
        self.ip = django_request.META.get("REMOTE_ADDR", "0.0.0.0")
        self._query = None
        self._form = None
        self._cookies = None
        self._headers = None
        self._raw_body = None

    @property
    def query(self) -> Dict[str, str]:
        if self._query is None:
            self._query = {k: deep_decode(v) for k, v in self._django.GET.items()}
        return self._query

    @property
    def form(self) -> Dict[str, str]:
        if self._form is None:
            self._form = {k: deep_decode(v) for k, v in self._django.POST.items()}
        return self._form

    @property
    def cookies(self) -> Dict[str, str]:
        if self._cookies is None:
            self._cookies = {k: deep_decode(v) for k, v in self._django.COOKIES.items()}
        return self._cookies

    @property
    def headers(self) -> Dict[str, str]:
        if self._headers is None:
            self._headers = {}
            for key, value in self._django.META.items():
                if key.startswith("HTTP_"):
                    name = key[5:].lower().replace("_", "-")
                    self._headers[name] = value
        return self._headers

    @property
    def raw_body(self) -> str:
        if self._raw_body is None:
            try:
                self._raw_body = self._django.body.decode("utf-8", errors="replace")
            except Exception:
                self._raw_body = ""
        return self._raw_body


class FlaskWafRequest(WafRequest):
    """Thin adapter over a Flask Request."""

    def __init__(self, flask_request):
        self._flask = flask_request
        self.method = flask_request.method.upper()
        self.path = flask_request.path
        self.user_agent = flask_request.headers.get("User-Agent", "")
        self.content_length = flask_request.content_length or 0
        self.ip = flask_request.remote_addr or "0.0.0.0"
        self._query = None
        self._form = None
        self._cookies = None
        self._headers = None
        self._raw_body = None

    @property
    def query(self) -> Dict[str, str]:
        if self._query is None:
            self._query = {k: deep_decode(v) for k, v in self._flask.args.items()}
        return self._query

    @property
    def form(self) -> Dict[str, str]:
        if self._form is None:
            self._form = {k: deep_decode(v) for k, v in self._flask.form.items()}
        return self._form

    @property
    def cookies(self) -> Dict[str, str]:
        if self._cookies is None:
            self._cookies = {k: deep_decode(v) for k, v in self._flask.cookies.items()}
        return self._cookies

    @property
    def headers(self) -> Dict[str, str]:
        if self._headers is None:
            self._headers = {k.lower(): v for k, v in self._flask.headers.items()}
        return self._headers

    @property
    def raw_body(self) -> str:
        if self._raw_body is None:
            try:
                self._raw_body = self._flask.get_data(as_text=True)
            except Exception:
                self._raw_body = ""
        return self._raw_body
