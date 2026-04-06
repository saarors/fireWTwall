from __future__ import annotations
import re
from typing import Dict, Optional
from ._base import DetectorResult

_REDIRECT_PARAMS = frozenset({
    "redirect", "return", "returnUrl", "return_url", "next", "continue",
    "target", "dest", "destination", "goto", "url", "uri", "href", "link",
    "location", "forward", "back", "to",
})

_EXTERNAL_RE = re.compile(r"^(?:https?:)?//(?!(?:localhost|127\.))", re.IGNORECASE)
_PROTO_RE    = re.compile(r"^(?:javascript|vbscript|data):", re.IGNORECASE)


class OpenRedirectDetector:
    @staticmethod
    def scan(sources: Dict[str, str]) -> Optional[DetectorResult]:
        for source, value in sources.items():
            if not value:
                continue
            key_lower = source.split(".")[-1].lower()
            if key_lower not in _REDIRECT_PARAMS:
                continue
            if _PROTO_RE.match(value):
                return DetectorResult(rule="open-redirect-proto", severity="high",
                                      matched=value[:120], source=source)
            if _EXTERNAL_RE.match(value):
                return DetectorResult(rule="open-redirect-external", severity="medium",
                                      matched=value[:120], source=source)
        return None
