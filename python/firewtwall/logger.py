from __future__ import annotations
import json
import os
import secrets
import threading
from datetime import datetime, timezone
from typing import Optional


_lock = threading.Lock()


class WafLogger:
    """Appends structured NDJSON entries to the WAF log file."""

    def __init__(self, log_path: str):
        self._log_path = log_path
        os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)

    def log_pass(self, ip: str, method: str, path: str,
                 user_agent: str = "", request_id: Optional[str] = None,
                 duration_ms: Optional[float] = None) -> None:
        entry: dict = {
            "timestamp": self._ts(),
            "requestId": request_id or self._rand_hex(),
            "result": "passed",
            "ip": ip,
            "method": method,
            "path": path,
        }
        if user_agent:
            entry["userAgent"] = user_agent
        if duration_ms is not None:
            entry["durationMs"] = round(duration_ms, 3)
        self._append(json.dumps(entry))

    def log_block(self, ip: str, method: str, path: str,
                  rule: str, matched: str = "", source: str = "",
                  severity: str = "medium", user_agent: str = "",
                  request_id: Optional[str] = None,
                  duration_ms: Optional[float] = None) -> None:
        entry: dict = {
            "timestamp": self._ts(),
            "requestId": request_id or self._rand_hex(),
            "result": "blocked",
            "ip": ip,
            "method": method,
            "path": path,
            "rule": rule,
            "severity": severity,
        }
        if source:
            entry["source"] = source
        if matched:
            entry["matched"] = matched[:120]
        if user_agent:
            entry["userAgent"] = user_agent
        if duration_ms is not None:
            entry["durationMs"] = round(duration_ms, 3)
        self._append(json.dumps(entry))

    def _append(self, line: str) -> None:
        try:
            with _lock:
                with open(self._log_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
        except Exception:
            pass  # never throw from logger

    @staticmethod
    def _ts() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def _rand_hex() -> str:
        return secrets.token_hex(8)
