from __future__ import annotations
import re
from typing import Dict, Optional
from ._base import DetectorResult, _scan

_F = re.IGNORECASE

_RULES = [
    ("cmdi-semicolon-cmd",  "critical", re.compile(r";\s*(?:ls|cat|id|whoami|pwd|uname|wget|curl|bash|sh|python|perl|ruby|php)\b", _F)),
    ("cmdi-pipe-cmd",       "critical", re.compile(r"\|\s*(?:ls|cat|id|whoami|bash|sh|nc|netcat)\b", _F)),
    ("cmdi-backtick",       "critical", re.compile(r"`[^`]+`")),
    ("cmdi-subshell",       "critical", re.compile(r"\$\([^)]+\)")),
    ("cmdi-logical-and",    "high",     re.compile(r"&&\s*(?:ls|cat|id|whoami|wget|curl)\b", _F)),
    ("cmdi-logical-or",     "high",     re.compile(r"\|\|\s*(?:ls|cat|id|whoami|wget|curl)\b", _F)),
    ("cmdi-redirection",    "high",     re.compile(r"[>|<]\s*/(?:etc|dev|tmp|var)/", _F)),
    ("cmdi-wget-curl",      "high",     re.compile(r"\b(?:wget|curl)\s+https?://", _F)),
    ("cmdi-netcat",         "critical", re.compile(r"\bnc\s+-[elp]", _F)),
    ("cmdi-chmod",          "high",     re.compile(r"\bchmod\s+[0-7]{3,4}\b", _F)),
    ("cmdi-chown",          "high",     re.compile(r"\bchown\s+\w+:\w+\b", _F)),
    ("cmdi-eval-exec",      "critical", re.compile(r"\b(?:eval|exec|system|passthru|popen|proc_open)\s*\(", _F)),
    ("cmdi-base64-decode",  "high",     re.compile(r"base64\s*-d", _F)),
    ("cmdi-env-override",   "medium",   re.compile(r"\benv\s+\w+=", _F)),
    ("cmdi-cron-inject",    "high",     re.compile(r"\bcrontab\b", _F)),
]


class CommandInjectionDetector:
    @staticmethod
    def scan(sources: Dict[str, str]) -> Optional[DetectorResult]:
        return _scan(_RULES, sources)
