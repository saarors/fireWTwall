from __future__ import annotations
import re
from typing import Dict, Optional
from ._base import DetectorResult, _scan

_F = re.IGNORECASE

_RULES = [
    ("mass-assign-admin",      "critical", re.compile(r'"(?:isAdmin|is_admin|admin|role|roles|permission|permissions|privilege|privileges)"\s*:\s*(?:true|1|"admin")', _F)),
    ("mass-assign-password",   "high",     re.compile(r'"(?:password|passwd|pwd|hashed_password|password_hash)"\s*:', _F)),
    ("mass-assign-id-field",   "medium",   re.compile(r'"(?:_?id|userId|user_id|accountId|account_id|ownerId|owner_id)"\s*:\s*\d+', _F)),
    ("mass-assign-balance",    "high",     re.compile(r'"(?:balance|credit|credits|points|score)"\s*:\s*\d+', _F)),
    ("mass-assign-verified",   "high",     re.compile(r'"(?:verified|email_verified|confirmed|active|enabled|banned|suspended)"\s*:\s*(?:true|false|1|0)', _F)),
    ("mass-assign-group",      "medium",   re.compile(r'"(?:group|groups|team|teams|org|organization)"\s*:', _F)),
    ("mass-assign-plan",       "medium",   re.compile(r'"(?:plan|tier|subscription|subscriptionType)"\s*:', _F)),
]


class MassAssignmentDetector:
    @staticmethod
    def scan(sources: Dict[str, str]) -> Optional[DetectorResult]:
        return _scan(_RULES, sources)
