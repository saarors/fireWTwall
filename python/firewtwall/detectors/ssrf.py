from __future__ import annotations
import re
import urllib.parse
from typing import Dict, Optional
from ._base import DetectorResult

_URL_PARAMS = frozenset({
    "url", "uri", "href", "src", "source", "dest", "destination", "redirect",
    "return", "returnUrl", "return_url", "next", "continue", "target",
    "link", "img", "image", "path", "file", "open", "load", "fetch",
    "proxy", "callback", "host", "domain", "site", "endpoint",
})

_PRIVATE_RE = re.compile(
    r"(?:"
    r"^https?://(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1)\b"
    r"|^https?://169\.254\.\d+\.\d+"         # link-local / AWS metadata
    r"|^https?://(?:10|192\.168|172\.1[6-9]|172\.2\d|172\.3[01])\."
    r"|^https?://[^/]*\.internal\b"
    r"|^https?://[^/]*\.local\b"
    r")",
    re.IGNORECASE,
)

_SCHEME_RE = re.compile(r"^(?:file|dict|gopher|ldap|ftp|jar|netdoc|sftp)://", re.IGNORECASE)


class SsrfDetector:
    @staticmethod
    def scan(sources: Dict[str, str]) -> Optional[DetectorResult]:
        for source, value in sources.items():
            if not value:
                continue
            # Only inspect values whose key smells like a URL parameter
            key_lower = source.split(".")[-1].lower()
            if key_lower not in _URL_PARAMS and not any(p in key_lower for p in ("url", "uri", "href", "src", "redirect")):
                continue
            if _SCHEME_RE.match(value):
                return DetectorResult(rule="ssrf-scheme", severity="critical",
                                      matched=value[:120], source=source)
            if _PRIVATE_RE.match(value):
                return DetectorResult(rule="ssrf-private-ip", severity="critical",
                                      matched=value[:120], source=source)

        # Second pass — scan everything for bare private addresses used in URL values
        for source, value in sources.items():
            if not value:
                continue
            if _PRIVATE_RE.search(value):
                return DetectorResult(rule="ssrf-private-ip", severity="high",
                                      matched=value[:120], source=source)

        return None
