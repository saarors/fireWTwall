from __future__ import annotations
import re
from typing import Dict, Optional
from ._base import DetectorResult, _scan

_F = re.IGNORECASE | re.DOTALL

_RULES = [
    ("xxe-doctype",       "critical", re.compile(r"<!DOCTYPE[^>]*\[", _F)),
    ("xxe-entity-decl",   "critical", re.compile(r"<!ENTITY\s+\S+\s+(?:SYSTEM|PUBLIC)\b", _F)),
    ("xxe-parameter-entity", "critical", re.compile(r"<!ENTITY\s+%\s+\S+", _F)),
    ("xxe-file-scheme",   "critical", re.compile(r"(?:SYSTEM|PUBLIC)\s+[\"']file://", _F)),
    ("xxe-php-filter",    "critical", re.compile(r"php://filter", _F)),
    ("xxe-expect",        "critical", re.compile(r"expect://", _F)),
    ("xxe-xinclude",      "high",     re.compile(r"<xi:include\s", _F)),
    ("xxe-external-dtd",  "high",     re.compile(r"SYSTEM\s+[\"']https?://", _F)),
]


class XxeDetector:
    @staticmethod
    def scan(sources: Dict[str, str]) -> Optional[DetectorResult]:
        return _scan(_RULES, sources)
