from __future__ import annotations
import re
from typing import Dict, Optional
from ._base import DetectorResult, _scan

_F = re.IGNORECASE

_RULES = [
    ("ldap-wildcard",       "high",     re.compile(r"\*(?:\)\(|\)|$)", _F)),
    ("ldap-logical-or",     "critical", re.compile(r"\|\(", _F)),
    ("ldap-logical-and",    "high",     re.compile(r"&\(", _F)),
    ("ldap-logical-not",    "high",     re.compile(r"!\(", _F)),
    ("ldap-attr-inject",    "critical", re.compile(r"\)\s*\(\s*\w+\s*=", _F)),
    ("ldap-null-byte",      "high",     re.compile(r"\\00", _F)),
    ("ldap-encoded-paren",  "high",     re.compile(r"\\(?:28|29|2a|5c)", _F)),
    ("ldap-object-class",   "medium",   re.compile(r"objectClass\s*=\s*\*", _F)),
    ("ldap-admin-query",    "critical", re.compile(r"\(cn=(?:admin|root|superuser)\)", _F)),
]


class LdapInjectionDetector:
    @staticmethod
    def scan(sources: Dict[str, str]) -> Optional[DetectorResult]:
        return _scan(_RULES, sources)
