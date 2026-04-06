from __future__ import annotations
import re
from typing import Dict, Optional
from ._base import DetectorResult, _scan

_F = re.IGNORECASE

_RULES = [
    ("log4shell-jndi",        "critical", re.compile(r"\$\{jndi:", _F)),
    ("log4shell-jndi-lower",  "critical", re.compile(r"\$\{[lL][oO][wW][eE][rR]:[^}]*jndi:", _F)),
    ("log4shell-jndi-upper",  "critical", re.compile(r"\$\{[uU][pP][pP][eE][rR]:[^}]*jndi:", _F)),
    ("log4shell-nested",      "critical", re.compile(r"\$\{\$\{.*\}", _F)),
    ("log4shell-encoded",     "critical", re.compile(r"%24%7bjndi%3a", _F)),
    ("log4shell-double-enc",  "critical", re.compile(r"%2524%257bjndi%253a", _F)),
    ("log4shell-ldap",        "critical", re.compile(r"\$\{.*ldap[s]?://", _F)),
    ("log4shell-rmi",         "critical", re.compile(r"\$\{.*rmi://", _F)),
    ("log4shell-dns",         "high",     re.compile(r"\$\{.*dns://", _F)),
]


class Log4ShellDetector:
    @staticmethod
    def scan(sources: Dict[str, str]) -> Optional[DetectorResult]:
        return _scan(_RULES, sources)
