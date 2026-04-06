from __future__ import annotations
import re
from typing import Dict, Optional
from ._base import DetectorResult, _scan

_F = re.IGNORECASE

_RULES = [
    ("ssti-jinja2",        "critical", re.compile(r"\{\{.{0,80}\}\}", _F)),
    ("ssti-jinja2-block",  "critical", re.compile(r"\{%.{0,80}%\}", _F)),
    ("ssti-twig",          "high",     re.compile(r"\{\{.{0,80}\|.{0,40}\}\}", _F)),
    ("ssti-freemarker",    "critical", re.compile(r"\$\{.{0,80}\}", _F)),
    ("ssti-velocity",      "high",     re.compile(r"#(?:set|if|foreach|macro|parse|include)\s*\(", _F)),
    ("ssti-mako",          "high",     re.compile(r"\$\{(?:self|context)\.", _F)),
    ("ssti-smarty",        "medium",   re.compile(r"\{(?:php|literal|assign|include)\}", _F)),
    ("ssti-pebble",        "medium",   re.compile(r"\{\{.{0,80}\}\}", _F)),
    ("ssti-thymeleaf",     "high",     re.compile(r"th:(?:text|utext|href|src|action)\s*=", _F)),
    ("ssti-erb",           "critical", re.compile(r"<%=.{0,80}%>", _F)),
    ("ssti-handlebars",    "medium",   re.compile(r"\{\{#(?:each|if|unless|with)\b", _F)),
    ("ssti-angularjs-expr","high",     re.compile(r"\{\{(?:constructor|__proto__|prototype)\b", _F)),
]


class SstiDetector:
    @staticmethod
    def scan(sources: Dict[str, str]) -> Optional[DetectorResult]:
        return _scan(_RULES, sources)
