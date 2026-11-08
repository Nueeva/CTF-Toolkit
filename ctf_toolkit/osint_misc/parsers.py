from __future__ import annotations

import json
import re
from typing import Any

from ctf_toolkit.osint_misc.config_hunter import extract_json_secrets


def ct_parser(data: list[dict[str, Any]] | str) -> list[str]:
    """Extract hostnames, subdomains, and embedded flags from Certificate Transparency (crt.sh) entries."""
    results: list[str] = []
    if isinstance(data, str):
        try:
            entries = json.loads(data)
        except Exception:
            return re.findall(r"(?:name_value|common_name|dns_names)\s*[:=]\s*['\"]?([^'\"\s,]+)", data)
    else:
        entries = data

    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict):
                nv = entry.get("name_value", "") or entry.get("common_name", "")
                if nv:
                    results.append(str(nv))
    return results


def whois_parser(raw_text: str) -> dict[str, str]:
    """Parse whois record text into structured key-value pairs."""
    record: dict[str, str] = {}
    for line in raw_text.splitlines():
        line = line.strip()
        if ":" in line and not line.startswith("%") and not line.startswith("#"):
            parts = line.split(":", 1)
            k = parts[0].strip().lower()
            v = parts[1].strip()
            if k and v:
                record[k] = v
                if k == "org-name":
                    record["org"] = v
                    record["organization"] = v
    return record


def html_comment_parser(html: str) -> list[str]:
    """Extract all HTML comment contents from an HTML document or archive snapshot."""
    comments = re.findall(r"<!--(.*?)-->", html, re.DOTALL)
    cleaned = []
    for c in comments:
        c_clean = c.strip()
        if c_clean:
            cleaned.append(c_clean)
            m = re.search(r"(?:token|flag|secret)\s*:\s*([a-zA-Z0-9_]+)", c_clean, re.IGNORECASE)
            if m:
                cleaned.append(m.group(1))
    return cleaned


def json_secrets(data: dict | list | str, keywords: list[str] | None = None) -> list[str]:
    """Convenience alias to extract_json_secrets for JSON OSINT dumps."""
    if isinstance(data, (dict, list)):
        import json
        data = json.dumps(data)
    results = extract_json_secrets(data)
    if keywords:
        results = [r for r in results if any(k.lower() in r.lower() for k in keywords)]
    return results


def landmark_matcher(clue_or_text: str | tuple[float, float]) -> str:
    """Resolve landmark name from clue description, plaque text, or coordinates."""
    if isinstance(clue_or_text, tuple):
        from ctf_toolkit.osint_misc.osint_helpers import lookup_city_by_coordinates
        lat, lon = clue_or_text
        return lookup_city_by_coordinates(lat, lon)

    text = str(clue_or_text)
    m = re.search(r"'([A-Za-z0-9_\s]+)'", text)
    if m:
        return m.group(1).strip().lower()

    landmarks = [
        ("monas", "monas"),
        ("borobudur", "borobudur"),
        ("prambanan", "prambanan"),
        ("eiffel", "eiffel"),
        ("colosseum", "colosseum"),
        ("liberty", "statue_of_liberty"),
        ("taj mahal", "taj_mahal"),
        ("fuji", "mount_fuji"),
        ("merlion", "merlion"),
    ]
    text_lower = text.lower()
    for name, slug in landmarks:
        if name in text_lower:
            return slug
    return "unknown"
