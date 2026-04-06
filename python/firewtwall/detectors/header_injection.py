from __future__ import annotations
import re
from typing import Dict, Optional
from ._base import DetectorResult, _scan

_F = re.IGNORECASE

_RULES = [
    ("header-crlf",          "critical", re.compile(r"(?:%0d%0a|%0a%0d|\r\n|\n\r|\r|\n)", _F)),
    ("header-newline-lf",    "critical", re.compile(r"%0[aA]")),
    ("header-newline-cr",    "critical", re.compile(r"%0[dD]")),
    ("header-set-cookie",    "high",     re.compile(r"Set-Cookie\s*:", _F)),
    ("header-location",      "high",     re.compile(r"Location\s*:\s*https?://", _F)),
    ("header-content-type",  "medium",   re.compile(r"Content-Type\s*:", _F)),
    ("header-x-inject",      "medium",   re.compile(r"X-[A-Za-z-]+\s*:", _F)),
]


class HeaderInjectionDetector:
    @staticmethod
    def scan(sources: Dict[str, str]) -> Optional[DetectorResult]:
        return _scan(_RULES, sources)
