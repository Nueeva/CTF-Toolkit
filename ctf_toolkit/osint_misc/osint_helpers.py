from __future__ import annotations

import math
import re

KNOWN_CITIES: list[tuple[float, float, str]] = [
    (57.79, -152.407, 'kodiak'),
    (-6.2088, 106.8456, 'jakarta'),
    (-7.7956, 110.3695, 'yogyakarta'),
    (-6.9175, 107.6191, 'bandung'),
    (-7.2575, 112.7521, 'surabaya'),
    (-6.9667, 110.4167, 'semarang'),
    (-7.9826, 112.6308, 'malang'),
    (-5.1477, 119.4327, 'makassar'),
    (3.5952, 98.6722, 'medan'),
    (-8.4095, 115.1889, 'bali'),
    (-8.65, 115.2167, 'denpasar'),
    (-0.9471, 100.4172, 'padang'),
    (-2.9909, 104.7565, 'palembang'),
    (-5.45, 105.2667, 'bandar_lampung'),
    (-0.0263, 109.3425, 'pontianak'),
    (-3.3194, 114.5908, 'banjarmasin'),
    (-1.2379, 116.8529, 'balikpapan'),
    (-0.5022, 117.1536, 'samarinda'),
    (1.4748, 124.8428, 'manado'),
    (-3.6547, 128.1906, 'ambon'),
    (-2.5337, 140.7181, 'jayapura'),
    (5.5483, 95.3238, 'banda_aceh'),
    (1.1301, 104.0529, 'batam'),
    (0.5071, 101.4478, 'pekanbaru'),
    (-1.6101, 103.6131, 'jambi'),
    (-3.7928, 102.2608, 'bengkulu'),
    (-2.129, 106.1139, 'pangkal_pinang'),
    (-6.5971, 106.806, 'bogor'),
    (-6.2383, 106.9756, 'bekasi'),
    (-6.4025, 106.7942, 'depok'),
    (-6.1783, 106.6319, 'tangerang'),
    (-6.2889, 106.7179, 'tangerang_selatan'),
    (-6.8361, 107.1425, 'cianjur'),
    (-6.9219, 106.9278, 'sukabumi'),
    (-6.732, 108.5523, 'cirebon'),
    (-7.3274, 108.2207, 'tasikmalaya'),
    (-7.5755, 110.8243, 'surakarta'),
    (-6.8898, 109.6753, 'pekalongan'),
    (-6.8797, 109.1256, 'tegal'),
    (-7.4243, 109.2302, 'purwokerto'),
    (-7.4706, 110.2178, 'magelang'),
    (-7.151, 111.8817, 'bojonegoro'),
    (-7.4726, 112.4385, 'mojokerto'),
    (-7.848, 112.0178, 'kediri'),
    (-7.6298, 111.5239, 'madiun'),
    (-8.1331, 113.2249, 'lumajang'),
    (-8.1724, 113.7008, 'jember'),
    (-8.2192, 114.3692, 'banyuwangi'),
    (-8.5833, 116.1167, 'mataram'),
    (-10.1772, 123.607, 'kupang'),
    (-0.9, 119.8333, 'palu'),
    (-3.9722, 122.515, 'kendari'),
    (0.5435, 123.0568, 'gorontalo'),
    (-2.6715, 118.8872, 'mamuju'),
    (0.7893, 127.361, 'ternate'),
    (-0.8615, 134.062, 'manokwari'),
    (-0.8833, 131.25, 'sorong'),
    (-8.4991, 140.4011, 'merauke'),
    (-4.095, 138.948, 'wamena'),
    (1.2897, 103.8501, 'singapore'),
    (3.139, 101.6869, 'kuala_lumpur'),
    (5.4164, 100.3327, 'penang'),
    (1.4927, 103.7414, 'johor_bahru'),
    (13.7563, 100.5018, 'bangkok'),
    (18.7061, 98.9817, 'chiang_mai'),
    (7.8804, 98.3923, 'phuket'),
    (14.5995, 120.9842, 'manila'),
    (10.3157, 123.8854, 'cebu'),
    (7.1907, 125.4553, 'davao'),
    (21.0285, 105.8542, 'hanoi'),
    (10.8231, 106.6297, 'ho_chi_minh'),
    (16.0544, 108.2022, 'da_nang'),
    (11.5564, 104.9282, 'phnom_penh'),
    (17.9757, 102.6331, 'vientiane'),
    (16.8409, 96.1735, 'yangon'),
    (19.7633, 96.0785, 'naypyidaw'),
    (4.9031, 114.9398, 'bandar_seri_begawan'),
    (-8.5586, 125.5736, 'dili'),
    (35.6762, 139.6503, 'tokyo'),
    (34.6937, 135.5023, 'osaka'),
    (35.0116, 135.7681, 'kyoto'),
    (37.5665, 126.978, 'seoul'),
    (35.1796, 129.0756, 'busan'),
    (39.9042, 116.4074, 'beijing'),
    (31.2304, 121.4737, 'shanghai'),
    (22.3193, 114.1694, 'hong_kong'),
    (25.033, 121.5654, 'taipei'),
    (28.6139, 77.209, 'new_delhi'),
    (19.076, 72.8777, 'mumbai'),
    (12.9716, 77.5946, 'bengaluru'),
    (24.8607, 67.0011, 'karachi'),
    (33.6844, 73.0479, 'islamabad'),
    (23.8103, 90.4125, 'dhaka'),
    (6.9271, 79.8612, 'colombo'),
    (27.7172, 85.324, 'kathmandu'),
    (25.2048, 55.2708, 'dubai'),
    (24.4539, 54.3773, 'abu_dhabi'),
    (24.7136, 46.6753, 'riyadh'),
    (21.4858, 39.1925, 'jeddah'),
    (25.2854, 51.531, 'doha'),
    (29.3759, 47.9774, 'kuwait_city'),
    (35.6892, 51.389, 'tehran'),
    (32.0853, 34.7818, 'tel_aviv'),
    (31.7683, 35.2137, 'jerusalem'),
    (33.5138, 36.2765, 'damascus'),
    (33.3152, 44.3661, 'baghdad'),
    (41.0082, 28.9784, 'istanbul'),
    (39.9334, 32.8597, 'ankara'),
    (51.5074, -0.1278, 'london'),
    (48.8566, 2.3522, 'paris'),
    (52.52, 13.405, 'berlin'),
    (48.1351, 11.582, 'munich'),
    (50.1109, 8.6821, 'frankfurt'),
    (52.3676, 4.9041, 'amsterdam'),
    (50.8503, 4.3517, 'brussels'),
    (41.9028, 12.4964, 'rome'),
    (45.4642, 9.19, 'milan'),
    (40.4168, -3.7038, 'madrid'),
    (41.3879, 2.1699, 'barcelona'),
    (38.7223, -9.1393, 'lisbon'),
    (48.2082, 16.3738, 'vienna'),
    (47.3769, 8.5417, 'zurich'),
    (46.2044, 6.1432, 'geneva'),
    (50.0755, 14.4378, 'prague'),
    (47.4979, 19.0402, 'budapest'),
    (52.2297, 21.0122, 'warsaw'),
    (59.3293, 18.0686, 'stockholm'),
    (59.9139, 10.7522, 'oslo'),
    (60.1699, 24.9384, 'helsinki'),
    (55.6761, 12.5683, 'copenhagen'),
    (53.3498, -6.2603, 'dublin'),
    (55.9533, -3.1883, 'edinburgh'),
    (37.9838, 23.7275, 'athens'),
    (44.4268, 26.1025, 'bucharest'),
    (42.6977, 23.3219, 'sofia'),
    (44.7866, 20.4489, 'belgrade'),
    (50.4501, 30.5234, 'kyiv'),
    (55.7558, 37.6173, 'moscow'),
    (59.9343, 30.3351, 'saint_petersburg'),
    (37.7749, -122.4194, 'san_francisco'),
    (37.3382, -121.8863, 'san_jose'),
    (36.1699, -115.1398, 'las_vegas'),
    (34.0522, -118.2437, 'los_angeles'),
    (32.7157, -117.1611, 'san_diego'),
    (47.6062, -122.3321, 'seattle'),
    (45.5152, -122.6784, 'portland'),
    (40.7128, -74.006, 'new_york'),
    (42.3601, -71.0589, 'boston'),
    (38.9072, -77.0369, 'washington_dc'),
    (41.8781, -87.6298, 'chicago'),
    (29.7604, -95.3698, 'houston'),
    (30.2672, -97.7431, 'austin'),
    (32.7767, -96.797, 'dallas'),
    (25.7617, -80.1918, 'miami'),
    (33.749, -84.388, 'atlanta'),
    (39.7392, -104.9903, 'denver'),
    (33.4484, -112.074, 'phoenix'),
    (43.6532, -79.3832, 'toronto'),
    (45.5017, -73.5673, 'montreal'),
    (49.2827, -123.1207, 'vancouver'),
    (45.4215, -75.6972, 'ottawa'),
    (19.4326, -99.1332, 'mexico_city'),
    (-23.5505, -46.6333, 'sao_paulo'),
    (-22.9068, -43.1729, 'rio_de_janeiro'),
    (-15.8267, -47.9218, 'brasilia'),
    (-34.6037, -58.3816, 'buenos_aires'),
    (-33.4489, -70.6693, 'santiago'),
    (-12.0464, -77.0428, 'lima'),
    (4.711, -74.0721, 'bogota'),
    (-33.8688, 151.2093, 'sydney'),
    (-37.8136, 144.9631, 'melbourne'),
    (-27.4698, 153.0251, 'brisbane'),
    (-31.9505, 115.8605, 'perth'),
    (-36.8485, 174.7633, 'auckland'),
    (-41.2865, 174.7762, 'wellington'),
    (30.0444, 31.2357, 'cairo'),
    (-26.2041, 28.0473, 'johannesburg'),
    (-33.9249, 18.4241, 'cape_town'),
    (-1.2921, 36.8219, 'nairobi'),
    (6.5244, 3.3792, 'lagos'),
    (33.5731, -7.5898, 'casablanca'),
]

def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate the great-circle distance between two points on Earth in kilometers."""
    r = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2.0) ** 2
    return 2.0 * r * math.asin(math.sqrt(max(0.0, min(1.0, a))))


def lookup_city_by_coordinates(lat: float, lon: float, tolerance: float = 0.5) -> str:
    """Resolve geographic latitude and longitude to the nearest known city name within tolerance degrees/distance."""
    best_city = "unknown"
    best_dist = float("inf")
    # 0.5 degrees is roughly 55 km
    max_km = max(55.0, tolerance * 111.0)

    for c_lat, c_lon, city in KNOWN_CITIES:
        # Check fast box first
        if abs(lat - c_lat) <= tolerance and abs(lon - c_lon) <= tolerance:
            dist = _haversine_km(lat, lon, c_lat, c_lon)
            if dist < best_dist:
                best_dist = dist
                best_city = city

    if best_city == "unknown":
        # Search all cities with haversine
        for c_lat, c_lon, city in KNOWN_CITIES:
            dist = _haversine_km(lat, lon, c_lat, c_lon)
            if dist <= max_km and dist < best_dist:
                best_dist = dist
                best_city = city

    return best_city


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
    return re.findall(r"(?:TECHCOMFEST\d*|COMPFEST\d*|GEMASTIK\d*|WRECKIT\d*|HOLOGY\d*|SLASHROOT\d*|GETSFLAG|CTFLEARN|picoCTF|SEKAI|HIDC\d*|ARA\d*|CHTB|HTB|THM|ASIS|DICE|HOPE|OOO|ARKAV|LACTF|ACTF|LKS|CTF|FLAG|CT)\{[^}]+\}", gitlog_text)


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


