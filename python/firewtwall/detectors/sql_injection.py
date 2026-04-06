from __future__ import annotations
import re
from typing import Dict, Optional
from ._base import DetectorResult, _scan

_F = re.IGNORECASE

_RULES = [
    ("sqli-union-select",   "critical", re.compile(r"union\s+(?:all\s+)?select\b", _F)),
    ("sqli-or-tautology",   "critical", re.compile(r"\bor\s+\d+\s*=\s*\d+", _F)),
    ("sqli-and-tautology",  "critical", re.compile(r"\band\s+\d+\s*=\s*\d+", _F)),
    ("sqli-sleep",          "high",     re.compile(r"\b(?:sleep|benchmark|waitfor\s+delay)\s*\(", _F)),
    ("sqli-drop",           "critical", re.compile(r"\bdrop\s+(?:table|database|schema)\b", _F)),
    ("sqli-insert",         "high",     re.compile(r"\binsert\s+into\b", _F)),
    ("sqli-update-set",     "high",     re.compile(r"\bupdate\s+\w+\s+set\b", _F)),
    ("sqli-delete-from",    "high",     re.compile(r"\bdelete\s+from\b", _F)),
    ("sqli-exec",           "critical", re.compile(r"\bexec(?:ute)?\s*\(", _F)),
    ("sqli-xp-cmdshell",    "critical", re.compile(r"\bxp_cmdshell\b", _F)),
    ("sqli-information-schema","high",  re.compile(r"\binformation_schema\b", _F)),
    ("sqli-sys-tables",     "high",     re.compile(r"\bsys(?:objects|tables|columns)\b", _F)),
    ("sqli-cast",           "medium",   re.compile(r"\bcast\s*\(.*\bas\b", _F)),
    ("sqli-convert",        "medium",   re.compile(r"\bconvert\s*\(", _F)),
    ("sqli-char-concat",    "medium",   re.compile(r"\bchar\s*\(\s*\d+", _F)),
    ("sqli-comment-bypass", "high",     re.compile(r"(?:--|#|/\*)", _F)),
    ("sqli-stacked",        "high",     re.compile(r";\s*(?:select|insert|update|delete|drop)\b", _F)),
    ("sqli-hex-value",      "medium",   re.compile(r"\b0x[0-9a-f]{4,}\b", _F)),
    ("sqli-load-file",      "critical", re.compile(r"\bload_file\s*\(", _F)),
    ("sqli-into-outfile",   "critical", re.compile(r"\binto\s+(?:outfile|dumpfile)\b", _F)),
    ("sqli-schema-dump",    "high",     re.compile(r"\bschema\s*\(\)", _F)),
    ("sqli-group-by-having","medium",   re.compile(r"\bhaving\s+\d+\s*=\s*\d+", _F)),
    ("sqli-extractvalue",   "high",     re.compile(r"\bextractvalue\s*\(", _F)),
    ("sqli-updatexml",      "high",     re.compile(r"\bupdatexml\s*\(", _F)),
    ("sqli-floor-rand",     "high",     re.compile(r"\bfloor\s*\(\s*rand\s*\(", _F)),
    ("sqli-error-based",    "high",     re.compile(r"\b(?:exp|ln|log)\s*\(\s*~", _F)),
    ("sqli-substring",      "medium",   re.compile(r"\bsubstr(?:ing)?\s*\(", _F)),
    ("sqli-ascii",          "medium",   re.compile(r"\bascii\s*\(", _F)),
    ("sqli-if-blind",       "high",     re.compile(r"\bif\s*\(\s*\d+\s*=\s*\d+", _F)),
    ("sqli-case-blind",     "high",     re.compile(r"\bcase\s+when\s+\d+\s*=\s*\d+", _F)),
    ("sqli-concat",         "medium",   re.compile(r"\bconcat\s*\(", _F)),
    ("sqli-group-concat",   "medium",   re.compile(r"\bgroup_concat\s*\(", _F)),
    ("sqli-order-by-num",   "medium",   re.compile(r"\border\s+by\s+\d+", _F)),
]


def scan(sources: Dict[str, str]) -> Optional[DetectorResult]:
    return _scan(_RULES, sources)


class SqlInjectionDetector:
    @staticmethod
    def scan(sources: Dict[str, str]) -> Optional[DetectorResult]:
        return scan(sources)
