from __future__ import annotations
import re
from typing import Dict, Optional
from ._base import DetectorResult, _scan

_F = re.IGNORECASE

_RULES = [
    ("rfi-http",           "critical", re.compile(r"(?:include|require)(?:_once)?\s*\(\s*[\"']https?://", _F)),
    ("rfi-ftp",            "critical", re.compile(r"(?:include|require)(?:_once)?\s*\(\s*[\"']ftp://", _F)),
    ("rfi-php-filter",     "critical", re.compile(r"php://(?:input|filter|data)", _F)),
    ("rfi-php-expect",     "critical", re.compile(r"php://(?:expect|zip)", _F)),
    ("rfi-data-uri",       "high",     re.compile(r"data://text/plain", _F)),
    ("rfi-zip-wrapper",    "high",     re.compile(r"zip://[^#]+#", _F)),
    ("rfi-phar",           "high",     re.compile(r"phar://", _F)),
    ("rfi-remote-include", "high",     re.compile(r"[?&](?:file|page|include|path|template)\s*=\s*https?://", _F)),
]


class RfiDetector:
    @staticmethod
    def scan(sources: Dict[str, str]) -> Optional[DetectorResult]:
        return _scan(_RULES, sources)
