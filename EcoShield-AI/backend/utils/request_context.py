"""Request context helpers: client IP, user-agent parsing, and a light-weight
geolocation approximation.

No external network calls are made. Country is approximated from IP range for
demo purposes; in production, plug in a real GeoIP provider here.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from fastapi import Request


@dataclass
class ClientContext:
    ip_address: str
    user_agent: str
    device_type: str
    browser: str
    os: str
    country: str


def get_client_ip(request: Request) -> str:
    """Best-effort client IP honouring a trusted reverse proxy header."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        # First entry is the original client when behind a proxy chain.
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "unknown"


def _parse_browser(ua: str) -> str:
    ua_l = ua.lower()
    if "edg/" in ua_l or "edge" in ua_l:
        return "Edge"
    if "opr/" in ua_l or "opera" in ua_l:
        return "Opera"
    if "chrome" in ua_l and "chromium" not in ua_l:
        return "Chrome"
    if "firefox" in ua_l:
        return "Firefox"
    if "safari" in ua_l:
        return "Safari"
    return "Unknown"


def _parse_os(ua: str) -> str:
    ua_l = ua.lower()
    if "windows" in ua_l:
        return "Windows"
    if "android" in ua_l:
        return "Android"
    if "iphone" in ua_l or "ipad" in ua_l or "ios" in ua_l:
        return "iOS"
    if "mac os" in ua_l or "macintosh" in ua_l:
        return "macOS"
    if "linux" in ua_l:
        return "Linux"
    return "Unknown"


def _parse_device(ua: str) -> str:
    ua_l = ua.lower()
    if any(t in ua_l for t in ("mobile", "iphone", "android", "ipod")):
        return "mobile"
    if any(t in ua_l for t in ("ipad", "tablet", "kindle", "silk")):
        return "tablet"
    if "bot" in ua_l or "crawler" in ua_l or "spider" in ua_l:
        return "bot"
    return "desktop"


def _approx_country(ip: str) -> str:
    """Deterministic offline approximation. Replace with a GeoIP service in prod."""
    if not ip or ip in ("unknown", "127.0.0.1", "::1", "testclient"):
        return "LOCAL"
    if re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", ip):
        return "LOCAL"
    # Stable pseudo-country derived from the first octet so the anomaly detector
    # has a consistent signal without calling an external API.
    m = re.match(r"^(\d{1,3})\.", ip)
    if m:
        first = int(m.group(1))
        table = ["US", "GB", "DE", "IN", "CN", "JP", "BR", "FR", "AU", "RU"]
        return table[first % len(table)]
    return "UNKNOWN"


def build_client_context(request: Request) -> ClientContext:
    ua = request.headers.get("user-agent", "")[:512]
    ip = get_client_ip(request)
    return ClientContext(
        ip_address=ip,
        user_agent=ua,
        device_type=_parse_device(ua),
        browser=_parse_browser(ua),
        os=_parse_os(ua),
        country=_approx_country(ip),
    )
