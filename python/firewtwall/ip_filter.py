from __future__ import annotations
import ipaddress
from typing import List, Optional


def ip_in_list(ip: str, lst: List[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in lst:
        if "/" in entry:
            try:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                pass
        elif ip == entry:
            return True
    return False


class IpFilter:
    """IP blacklist / whitelist filter with CIDR support (IPv4 and IPv6)."""

    def __init__(self, whitelist: List[str], blacklist: List[str]):
        self._whitelist = whitelist or []
        self._blacklist = blacklist or []

    def check(self, ip: str) -> Optional[str]:
        """Returns 'whitelist', 'blacklist', or None."""
        if self._whitelist and ip_in_list(ip, self._whitelist):
            return "whitelist"
        if self._blacklist and ip_in_list(ip, self._blacklist):
            return "blacklist"
        return None
