from __future__ import annotations
import re
from typing import Dict, Optional
from ._base import DetectorResult, _scan

_F = re.IGNORECASE

_RULES = [
    ("deser-java-serial",    "critical", re.compile(r"rO0AB", _F)),              # base64 Java serial
    ("deser-java-hex",       "critical", re.compile(r"aced0005", _F)),            # Java serial magic hex
    ("deser-php-object",     "critical", re.compile(r'O:\d+:"[A-Za-z_\\\\]+"\s*:\s*\d+:\s*\{', _F)),
    ("deser-php-array",      "high",     re.compile(r'a:\d+:\{', _F)),
    ("deser-python-pickle",  "critical", re.compile(r"\\x80[\\x01-\\x05]", _F)),
    ("deser-yaml-python",    "critical", re.compile(r"!!python/object", _F)),
    ("deser-yaml-apply",     "critical", re.compile(r"!!python/object/apply:", _F)),
    ("deser-net-binary",     "critical", re.compile(r"AAEAAAD", _F)),             # base64 .NET BinaryFormatter
    ("deser-viewstate",      "high",     re.compile(r"__VIEWSTATE\s*=", _F)),
    ("deser-json-net",       "high",     re.compile(r'"\$type"\s*:\s*"System\.', _F)),
    ("deser-xmlserializer",  "high",     re.compile(r"<ArrayOfAnyType\b", _F)),
    ("deser-ruby-marshal",   "high",     re.compile(r"\\x04\\x08", _F)),          # Ruby Marshal magic
    ("deser-node-proto",     "critical", re.compile(r"__proto__\s*:", _F)),
    ("deser-constructor",    "critical", re.compile(r'"constructor"\s*:', _F)),
]


class DeserializationDetector:
    @staticmethod
    def scan(sources: Dict[str, str]) -> Optional[DetectorResult]:
        return _scan(_RULES, sources)
