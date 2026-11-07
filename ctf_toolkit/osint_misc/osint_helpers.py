from __future__ import annotations

import re

KNOWN_CITIES: list[tuple[float, float, str]] = [
    (-6.2088, 106.8456, "jakarta"),
    (-7.7956, 110.3695, "yogyakarta"),
    (-6.9175, 107.6191, "bandung"),
    (-7.2575, 112.7521, "surabaya"),
    (1.2897, 103.8501, "singapore"),
    (35.6762, 139.6503, "tokyo"),
    (-8.4095, 115.1889, "bali"),
    (-6.9667, 110.4167, "semarang"),
    (-7.9826, 112.6308, "malang"),
    (-5.1477, 119.4327, "makassar"),
    (3.5952, 98.6722, "medan"),
]


def lookup_city_by_coordinates(lat: float, lon: float, tolerance: float = 0.5) -> str:
    """Resolve geographic latitude and longitude to the nearest known city name within tolerance."""
    for c_lat, c_lon, city in KNOWN_CITIES:
        if abs(lat - c_lat) <= tolerance and abs(lon - c_lon) <= tolerance:
            return city
    return "unknown"


def detect_os_from_user_agent(ua: str) -> str:
    """Identify the operating system family and version slug from an HTTP User-Agent string."""
    ua_lower = ua.lower()
    if "windows nt 10.0" in ua_lower:
        return "windows_10"
    if "windows nt 6.3" in ua_lower:
        return "windows_8_1"
    if "windows nt 6.1" in ua_lower:
        return "windows_7"
    if "mac os x 13" in ua_lower:
        return "macos_13"
    if "mac os x 14" in ua_lower:
        return "macos_14"
    if "mac os x 12" in ua_lower:
        return "macos_12"
    if "android 13" in ua_lower:
        return "android_13"
    if "android 14" in ua_lower:
        return "android_14"
    if "android 12" in ua_lower:
        return "android_12"
    if "linux" in ua_lower:
        return "linux"
    if "iphone" in ua_lower:
        return "ios"
    return "unknown"


def extract_received_sender_ip(eml_text: str) -> str | None:
    """Extract the first originating sender IP from email Received: header lines."""
    m = re.search(r"Received:\s+from\s+.*?\[([0-9]{1,3}(?:\.[0-9]{1,3}){3})\]", eml_text, re.IGNORECASE)
    return m.group(1) if m else None


def extract_san_subdomains(cert_text: str) -> list[str]:
    """Parse Subject Alternative Name (SAN) DNS entries from text certificate representations."""
    dns_entries = re.findall(r"DNS:([a-zA-Z0-9.-]+)", cert_text)
    return dns_entries
