from __future__ import annotations
import re
from typing import Dict, Optional
from ._base import DetectorResult, _scan

_F = re.IGNORECASE | re.DOTALL

_RULES = [
    ("xss-script-tag",       "critical", re.compile(r"<\s*script[\s>]", _F)),
    ("xss-script-src",       "critical", re.compile(r"<\s*script[^>]*src\s*=", _F)),
    ("xss-on-event",         "high",     re.compile(r"\bon(?:load|error|click|mouse\w+|key\w+|focus|blur|change|submit|reset|select|dblclick|drag\w*|drop|input|invalid|scroll|toggle|wheel)\s*=", _F)),
    ("xss-javascript-uri",   "critical", re.compile(r"javascript\s*:", _F)),
    ("xss-vbscript-uri",     "critical", re.compile(r"vbscript\s*:", _F)),
    ("xss-data-uri",         "high",     re.compile(r"data\s*:.*base64", _F)),
    ("xss-expression",       "high",     re.compile(r"expression\s*\(", _F)),
    ("xss-iframe",           "high",     re.compile(r"<\s*i?frame[\s>]", _F)),
    ("xss-svg-onload",       "critical", re.compile(r"<\s*svg[^>]*onload\s*=", _F)),
    ("xss-img-onerror",      "high",     re.compile(r"<\s*img[^>]*onerror\s*=", _F)),
    ("xss-object-tag",       "high",     re.compile(r"<\s*object[\s>]", _F)),
    ("xss-embed-tag",        "high",     re.compile(r"<\s*embed[\s>]", _F)),
    ("xss-link-tag",         "medium",   re.compile(r"<\s*link[^>]+rel\s*=\s*[\"']?stylesheet", _F)),
    ("xss-base-tag",         "medium",   re.compile(r"<\s*base[^>]+href\s*=", _F)),
    ("xss-html-entity-hack", "medium",   re.compile(r"&#\s*x?[0-9a-f]+;", _F)),
    ("xss-template-literal", "medium",   re.compile(r"`[^`]*\$\{[^}]+\}[^`]*`", _F)),
    ("xss-dom-write",        "high",     re.compile(r"document\s*\.\s*(?:write|writeln)\s*\(", _F)),
    ("xss-inner-html",       "high",     re.compile(r"\.innerHTML\s*=", _F)),
    ("xss-eval",             "high",     re.compile(r"\beval\s*\(", _F)),
    ("xss-alert",            "medium",   re.compile(r"\balert\s*\(", _F)),
    ("xss-prompt-confirm",   "medium",   re.compile(r"\b(?:prompt|confirm)\s*\(", _F)),
]


class XssDetector:
    @staticmethod
    def scan(sources: Dict[str, str]) -> Optional[DetectorResult]:
        return _scan(_RULES, sources)
