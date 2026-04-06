from __future__ import annotations
import re
from typing import Dict, Optional
from ._base import DetectorResult, _scan

_RULES = [
    ("shellshock-basic",   "critical", re.compile(r"\(\s*\)\s*\{")),
    ("shellshock-encoded", "critical", re.compile(r"%28%29%20%7b|%28%29%7b", re.IGNORECASE)),
    ("shellshock-func",    "critical", re.compile(r"\(\s*\)\s*\{[^}]*;[^}]*\}")),
]


class ShellshockDetector:
    @staticmethod
    def scan(sources: Dict[str, str]) -> Optional[DetectorResult]:
        return _scan(_RULES, sources)
