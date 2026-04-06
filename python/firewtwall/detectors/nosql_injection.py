from __future__ import annotations
import re
from typing import Dict, Optional
from ._base import DetectorResult, _scan

_F = re.IGNORECASE

_RULES = [
    ("nosql-where",       "critical", re.compile(r"\$where\s*:", _F)),
    ("nosql-regex",       "high",     re.compile(r"\$regex\s*:", _F)),
    ("nosql-ne",          "high",     re.compile(r"\$ne\s*:\s*(?:null|\"\"|\d+)", _F)),
    ("nosql-gt-lt",       "high",     re.compile(r"\$(?:gt|lt|gte|lte)\s*:", _F)),
    ("nosql-in",          "medium",   re.compile(r"\$in\s*:\s*\[", _F)),
    ("nosql-nin",         "medium",   re.compile(r"\$nin\s*:\s*\[", _F)),
    ("nosql-or",          "high",     re.compile(r"\$or\s*:\s*\[", _F)),
    ("nosql-and",         "medium",   re.compile(r"\$and\s*:\s*\[", _F)),
    ("nosql-expr",        "critical", re.compile(r"\$expr\s*:", _F)),
    ("nosql-function",    "critical", re.compile(r"function\s*\(", _F)),
    ("nosql-sleep",       "critical", re.compile(r"sleep\s*\(\s*\d+", _F)),
    ("nosql-tojson",      "high",     re.compile(r"(?:this|db)\.\w+\.(?:find|insert|update|remove)\s*\(", _F)),
]


class NoSqlInjectionDetector:
    @staticmethod
    def scan(sources: Dict[str, str]) -> Optional[DetectorResult]:
        return _scan(_RULES, sources)
