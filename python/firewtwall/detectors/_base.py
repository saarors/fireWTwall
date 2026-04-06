from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class DetectorResult:
    rule: str
    severity: str
    matched: str
    source: str


def _scan(rules: List[Tuple[str, str, re.Pattern]],
          sources: Dict[str, str]) -> Optional[DetectorResult]:
    for rule, severity, pattern in rules:
        for source, value in sources.items():
            if not value:
                continue
            m = pattern.search(value)
            if m:
                return DetectorResult(
                    rule=rule,
                    severity=severity,
                    matched=m.group(0)[:120],
                    source=source,
                )
    return None
