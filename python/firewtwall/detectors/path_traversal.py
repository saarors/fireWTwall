from __future__ import annotations
import re
from typing import Dict, Optional
from ._base import DetectorResult, _scan

_F = re.IGNORECASE

_RULES = [
    ("path-dotdot-slash",      "critical", re.compile(r"\.\./", _F)),
    ("path-dotdot-backslash",  "critical", re.compile(r"\.\.[/\\\\]", _F)),
    ("path-encoded-dotdot",    "critical", re.compile(r"%2e%2e[%2f%5c]", _F)),
    ("path-double-encoded",    "high",     re.compile(r"%252e%252e", _F)),
    ("path-etc-passwd",        "critical", re.compile(r"/etc/passwd", _F)),
    ("path-etc-shadow",        "critical", re.compile(r"/etc/shadow", _F)),
    ("path-proc-self",         "high",     re.compile(r"/proc/self/", _F)),
    ("path-win-system32",      "critical", re.compile(r"windows[/\\\\]system32", _F)),
    ("path-win-ini",           "high",     re.compile(r"(?:win\.ini|boot\.ini)", _F)),
    ("path-absolute-unix",     "high",     re.compile(r"^/(?:etc|var|usr|tmp|root|home)/", _F)),
    ("path-absolute-win",      "high",     re.compile(r"[a-z]:[/\\\\]", _F)),
    ("path-null-byte",         "high",     re.compile(r"%00", _F)),
    ("path-overlong-utf8",     "medium",   re.compile(r"%c0%ae|%c0%af|%e0%80%ae", _F)),
    ("path-unicode-sep",       "medium",   re.compile(r"%u2215|%u2216", _F)),
    ("path-ssh-keys",          "critical", re.compile(r"/\.ssh/(?:authorized_keys|id_rsa)", _F)),
    ("path-htaccess",          "high",     re.compile(r"/\.htaccess", _F)),
    ("path-env-file",          "high",     re.compile(r"/\.env\b", _F)),
]


class PathTraversalDetector:
    @staticmethod
    def scan(sources: Dict[str, str]) -> Optional[DetectorResult]:
        return _scan(_RULES, sources)
