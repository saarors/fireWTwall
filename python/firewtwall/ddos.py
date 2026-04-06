from __future__ import annotations
import threading
import time
from dataclasses import dataclass
from typing import Optional, Dict, Any

from .config import DdosConfig
from .request import WafRequest


@dataclass
class DdosResult:
    blocked: bool
    status: int           # HTTP status code when blocked
    rule: str
    retry_after: int = 0


class DdosProtection:
    """
    7-layer DDoS / abuse protection.

    Layer 1  — URL too long                     → 414
    Layer 2  — Too many request headers         → 431
    Layer 3  — Oversized header value           → 431
    Layer 4  — Per-IP burst (sliding window)    → 429
    Layer 5  — Global flood                     → 503
    Layer 6  — Per-fingerprint flood            → 429
    Layer 7  — Per-path flood                   → 503
    """

    def __init__(self, config: DdosConfig):
        self._cfg = config
        self._store: Dict[str, Any] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #

    def check(self, req: WafRequest) -> Optional[DdosResult]:
        # Layer 1 — URL length
        full_url = req.path
        qs = req._environ.get("QUERY_STRING", "")
        if qs:
            full_url += "?" + qs
        if len(full_url) > self._cfg.max_url_length:
            return DdosResult(blocked=True, status=414, rule="ddos-url-length")

        # Layer 2 — header count
        hdr_count = sum(1 for k in req._environ if k.startswith("HTTP_"))
        if hdr_count > self._cfg.max_headers_count:
            return DdosResult(blocked=True, status=431, rule="ddos-header-count")

        # Layer 3 — individual header size
        for key, val in req._environ.items():
            if key.startswith("HTTP_") and len(val) > self._cfg.max_header_size:
                return DdosResult(blocked=True, status=431, rule="ddos-header-size")

        now = time.time()

        with self._lock:
            # Layer 4 — per-IP burst
            ip_key = "ip_" + req.ip
            res = self._sliding(ip_key, now,
                                self._cfg.burst_window_sec,
                                self._cfg.burst_max_requests,
                                self._cfg.burst_block_sec)
            if res:
                return DdosResult(blocked=True, status=429, rule="ddos-burst",
                                  retry_after=res)

            # Layer 5 — global flood
            res = self._sliding("global", now,
                                self._cfg.global_window_sec,
                                self._cfg.global_max_requests, 30)
            if res:
                return DdosResult(blocked=True, status=503, rule="ddos-global-flood")

            # Layer 6 — per-fingerprint flood
            fp = self._fingerprint(req)
            res = self._sliding("fp_" + fp, now,
                                self._cfg.fp_window_sec,
                                self._cfg.fp_max_requests,
                                self._cfg.fp_block_sec)
            if res:
                return DdosResult(blocked=True, status=429, rule="ddos-fingerprint",
                                  retry_after=res)

            # Layer 7 — per-path flood
            path_key = "path_" + req.path
            res = self._sliding(path_key, now,
                                self._cfg.path_window_sec,
                                self._cfg.path_max_requests, 30)
            if res:
                return DdosResult(blocked=True, status=503, rule="ddos-path-flood")

        return None

    # ------------------------------------------------------------------ #

    def _sliding(self, key: str, now: float,
                 window: int, limit: int, block_sec: int) -> int:
        """
        Sliding-window helper.  Returns retry_after (int) if limit exceeded, else 0.
        Must be called inside self._lock.
        """
        bkey = "bl_" + key
        blocked_until = self._store.get(bkey)
        if blocked_until and now < blocked_until:
            return int(blocked_until - now)

        entry = self._store.get(key)
        if not entry or (now - entry["start"]) >= window:
            entry = {"start": now, "count": 0}

        entry["count"] += 1
        self._store[key] = entry

        if entry["count"] > limit:
            self._store[bkey] = now + block_sec
            return block_sec

        return 0

    @staticmethod
    def _fingerprint(req: WafRequest) -> str:
        ua = req.user_agent[:64]
        accept = req._environ.get("HTTP_ACCEPT", "")[:32]
        lang = req._environ.get("HTTP_ACCEPT_LANGUAGE", "")[:16]
        return f"{req.ip}:{ua}:{accept}:{lang}"
