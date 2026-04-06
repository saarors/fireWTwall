from __future__ import annotations
import hashlib
import threading
import time
from dataclasses import dataclass
from typing import Dict, Any

from .config import RateLimitConfig


@dataclass
class RateLimitResult:
    allowed: bool
    remaining: int
    retry_after: int


class RateLimiter:
    """
    Sliding-window rate limiter backed by an in-memory dict.
    Thread-safe. For multi-process deployments, swap _store for a Redis backend.
    """

    def __init__(self, config: RateLimitConfig):
        self._window_sec = config.window_sec
        self._max_requests = config.max_requests
        self._block_duration_sec = config.block_duration_sec
        self._store: Dict[str, Any] = {}
        self._lock = threading.Lock()

    def check(self, ip: str) -> RateLimitResult:
        key = "rl_" + self._md5(ip)
        bkey = "bl_" + self._md5(ip)
        now = time.time()

        with self._lock:
            # Blocked?
            blocked = self._store.get(bkey)
            if blocked and now < blocked:
                retry = int(blocked - now)
                return RateLimitResult(allowed=False, remaining=0, retry_after=retry)

            entry = self._store.get(key)
            if not entry or (now - entry["start"]) >= self._window_sec:
                entry = {"start": now, "count": 0}

            entry["count"] += 1
            self._store[key] = entry

            if entry["count"] > self._max_requests:
                self._store[bkey] = now + self._block_duration_sec
                return RateLimitResult(
                    allowed=False, remaining=0, retry_after=self._block_duration_sec
                )

            remaining = max(0, self._max_requests - entry["count"])
            return RateLimitResult(allowed=True, remaining=remaining, retry_after=0)

    @staticmethod
    def _md5(value: str) -> str:
        return hashlib.md5(value.encode()).hexdigest()
