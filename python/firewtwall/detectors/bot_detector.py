from __future__ import annotations
import re
from typing import Dict, List, Optional
from ._base import DetectorResult

# Default bad-bot signatures (case-insensitive substring match on User-Agent)
_DEFAULT_BAD_BOTS: List[str] = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "acunetix", "nessus",
    "openvas", "w3af", "dirbuster", "gobuster", "wfuzz", "ffuf", "feroxbuster",
    "nuclei", "burpsuite", "zap", "zaproxy", "owasp", "havij", "pangolin",
    "httprint", "whatweb", "joomscan", "wpscan", "droopescan", "cmseek",
    "vega", "arachni", "skipfish", "webscarab", "paros", "webinspect",
    "appscan", "netsparker", "sentinel", "webfuzz", "brutus", "hydra",
    "medusa", "aircrack", "metasploit", "msfconsole", "meterpreter",
    "python-requests/2.1", "python-httpx", "go-http-client/1", "libwww-perl",
    "lwp-request", "lwp-trivial", "curl/7.2", "curl/7.3", "curl/7.4",
    "peach", "grabber", "whisker", "rat proxy", "padbuster",
    "exploit", "scanner", "crawler/bot", "research-scan",
    "zgrab2", "x-scan", "masscan", "voideye", "proxystrike",
    "sitechecker", "semrushbot", "ahrefsbot", "dotbot",
    "rogerbot", "mj12bot", "blexbot", "serpstatbot", "seokicks",
    "babbar", "siteauditbot", "petalbot", "yandexbot",
    "baiduspider", "sogou", "exabot", "uptimerobot",
    "scrapy", "mechanize", "pycurl", "java/1.8", "java/11",
    "jakarta commons-httpclient", "apachebench", "ab/",
    "httpclient", "okhttp", "axios/0", "got/",
    "dataprovider.com", "panscient", "surdotly",
    "checkmarknetwork", "mauibot", "pinterestbot",
]

_DEFAULT_RE: re.Pattern = re.compile(
    "|".join(re.escape(b) for b in _DEFAULT_BAD_BOTS),
    re.IGNORECASE,
)

# Empty / suspicious user-agents
_EMPTY_UA_RULE    = "bot-empty-ua"
_MATCHED_UA_RULE  = "bot-bad-ua"


class BotDetector:
    def __init__(self, bad_bots: Optional[List[str]] = None):
        if bad_bots is not None:
            self._pattern: re.Pattern = re.compile(
                "|".join(re.escape(b) for b in bad_bots),
                re.IGNORECASE,
            )
        else:
            self._pattern = _DEFAULT_RE

    def scan(self, user_agent: str) -> Optional[DetectorResult]:
        if not user_agent or len(user_agent.strip()) < 4:
            return DetectorResult(rule=_EMPTY_UA_RULE, severity="medium",
                                  matched="", source="user-agent")
        m = self._pattern.search(user_agent)
        if m:
            return DetectorResult(rule=_MATCHED_UA_RULE, severity="high",
                                  matched=m.group(0)[:120], source="user-agent")
        return None
