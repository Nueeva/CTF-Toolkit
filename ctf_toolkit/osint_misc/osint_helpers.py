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
    (48.8566, 2.3522, "paris"),
    (51.5074, -0.1278, "london"),
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
    dns_entries = re.findall(r"DNS:([^\s,]+)", cert_text)
    return [d.strip() for d in dns_entries if d.strip()]


def extract_git_secret_from_config(config_text: str) -> str | None:
    """Extract embedded secret token or password from .git/config remote URLs."""
    m = re.search(r"url\s*=\s*https?://[^:]+:([^@]+)@", config_text)
    return m.group(1) if m else None


def parse_ctlog_entries(ctlog_text: str) -> list[str]:
    """Extract hostnames from Certificate Transparency log dump text."""
    return re.findall(r"(?:id=\d+\s*\|\s*|staging\s*:\s*)([a-zA-Z0-9.-]+)", ctlog_text)


def classify_login_ip(ip: str) -> str:
    """Classify suspicious login IP into archetypes (e.g., tor_exit, google_dns, indonesia_isp)."""
    if ip.startswith("185.220.") or ip.startswith("185.246."):
        return "tor_exit"
    if ip in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"):
        return "google_dns" if "8.8" in ip else "public_dns"
    if ip.startswith("103.10.") or ip.startswith("36.68.") or ip.startswith("180.252."):
        return "indonesia_isp"
    return "unknown"


def extract_git_commit_secrets(gitlog_text: str) -> list[str]:
    """Extract flags or tokens mentioned in git commit history messages."""
    return re.findall(r"(?:FLAG\{[^}]+\}|GETSFLAG\{[^}]+\})", gitlog_text)


def extract_tls_subject_cn(cert_text: str) -> str | None:
    """Extract Common Name (CN) from TLS subject field."""
    m = re.search(r"subject\s*=\s*CN\s*=\s*([^\r\n]+)", cert_text, re.IGNORECASE)
    return m.group(1).strip() if m else None


def extract_redirect_hop_notes(redirect_data: dict) -> list[str]:
    """Collect note fields across all hops in a shortlink redirect trace."""
    notes = []
    for hop in redirect_data.get("hops", []):
        if "note" in hop:
            notes.append(hop["note"])
    return notes


def extract_package_event_notes(track_data: dict) -> list[str]:
    """Collect signature and event notes from shipping tracking event records."""
    notes = []
    for ev in track_data.get("events", []):
        if "signature_note" in ev:
            notes.append(ev["signature_note"])
    return notes


