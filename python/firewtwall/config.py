from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import List


@dataclass
class DdosBurstConfig:
    window_sec: int = 1
    max_requests: int = 20
    block_duration_sec: int = 60


@dataclass
class DdosGlobalConfig:
    window_sec: int = 1
    max_requests: int = 500


@dataclass
class DdosFingerprintConfig:
    window_sec: int = 10
    max_requests: int = 50
    block_duration_sec: int = 60


@dataclass
class DdosPathFloodConfig:
    window_sec: int = 5
    max_requests: int = 200


@dataclass
class DdosTarpitConfig:
    enabled: bool = False
    delay_ms: int = 2000


@dataclass
class DdosConfig:
    max_url_length: int = 2048
    max_header_count: int = 100
    max_header_size: int = 8192
    burst: DdosBurstConfig = field(default_factory=DdosBurstConfig)
    global_: DdosGlobalConfig = field(default_factory=DdosGlobalConfig)
    fingerprint: DdosFingerprintConfig = field(default_factory=DdosFingerprintConfig)
    path_flood: DdosPathFloodConfig = field(default_factory=DdosPathFloodConfig)
    tarpit: DdosTarpitConfig = field(default_factory=DdosTarpitConfig)


@dataclass
class RateLimitConfig:
    window_sec: int = 60
    max_requests: int = 100
    block_duration_sec: int = 600


@dataclass
class WafConfig:
    """
    Centralised WAF configuration.

    Usage — Django (settings.py):
        FIREWTWALL = {
            "mode": "log-only",
            "rate_limit": {"max_requests": 200},
        }

    Usage — Flask / WSGI:
        config = WafConfig(mode="log-only")
        config.rate_limit.max_requests = 200
    """

    # 'reject' → block and return 4xx | 'log-only' → log but let request through
    mode: str = "reject"

    # Maximum Content-Length in bytes (default: 10 MB)
    max_body_size: int = 10 * 1024 * 1024

    # Permitted HTTP methods — anything else → 405
    allowed_methods: List[str] = field(
        default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
    )

    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    ddos: DdosConfig = field(default_factory=DdosConfig)

    # IPs / CIDR ranges that bypass all checks
    whitelist: List[str] = field(default_factory=list)

    # IPs / CIDR ranges that are always blocked
    blacklist: List[str] = field(default_factory=list)

    # URL path prefixes that skip all WAF checks
    bypass_paths: List[str] = field(default_factory=lambda: ["/health", "/ping"])

    # Trusted reverse-proxy IPs — enables X-Forwarded-For parsing
    trusted_proxies: List[str] = field(default_factory=list)

    # Log file path (must be writable by the web server process)
    log_path: str = os.path.join(os.path.dirname(__file__), "..", "logs", "waf.log")

    # Block response format: 'json' or 'html'
    response_type: str = "json"

    # Debug mode: log every request and add X-WAF-* response headers
    # Never enable in production — exposes rule names to the caller
    debug: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> "WafConfig":
        """Build a WafConfig from a plain dict (e.g. Django FIREWTWALL setting)."""
        cfg = cls()
        for key, value in d.items():
            if key == "rate_limit" and isinstance(value, dict):
                for k, v in value.items():
                    setattr(cfg.rate_limit, k, v)
            elif key == "ddos" and isinstance(value, dict):
                pass  # deep ddos override not needed for typical use
            elif hasattr(cfg, key):
                setattr(cfg, key, value)
        return cfg
