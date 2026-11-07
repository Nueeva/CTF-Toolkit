from __future__ import annotations

import json
import re
from typing import Any

DEFAULT_KEYWORDS = [
    "flag",
    "secret",
    "key",
    "token",
    "password",
    "pass",
    "auth",
    "cred",
    "api_key",
    "private",
]


def find_nested_secrets(
    obj: Any,
    target_keywords: list[str] | None = None,
    path: str = "",
) -> list[tuple[str, str]]:
    """
    Recursively traverse dictionaries and lists searching for secrets or flags
    embedded in deep configuration structures.
    Returns a list of (json_path, value_str).
    """
    keywords = [k.lower() for k in (target_keywords or DEFAULT_KEYWORDS)]
    findings: list[tuple[str, str]] = []

    if isinstance(obj, dict):
        for k, v in obj.items():
            curr_path = f"{path}.{k}" if path else str(k)
            # Check key name
            k_lower = str(k).lower()
            if any(kw in k_lower for kw in keywords) and isinstance(v, (str, int, float, bool)):
                findings.append((curr_path, str(v)))
            # Recurse
            findings.extend(find_nested_secrets(v, target_keywords, curr_path))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            curr_path = f"{path}[{idx}]"
            findings.extend(find_nested_secrets(item, target_keywords, curr_path))
    elif isinstance(obj, str):
        # Check if value matches flag format or secret keyword
        if re.search(r"(?:GETSFLAG|FLAG|CTF)\{[^}]+\}", obj):
            findings.append((path, obj))

    return findings


def extract_yaml_secrets(yaml_data: str | bytes) -> list[tuple[str, str]]:
    """
    Parse a YAML configuration document and extract secret keys and flag values.
    """
    try:
        import yaml
    except ImportError:
        # Fallback regex extraction if PyYAML is unavailable
        raw = yaml_data.decode("utf-8") if isinstance(yaml_data, bytes) else yaml_data
        matches = re.findall(r"(?:GETSFLAG|FLAG|CTF)\{[^}]+\}", raw)
        return [("raw_regex", m) for m in matches]

    raw = yaml_data.decode("utf-8") if isinstance(yaml_data, bytes) else yaml_data
    docs = yaml.safe_load_all(raw)
    all_findings: list[tuple[str, str]] = []
    for doc in docs:
        if doc is not None:
            all_findings.extend(find_nested_secrets(doc))
    return all_findings


def extract_json_secrets(json_data: str | bytes) -> list[tuple[str, str]]:
    """
    Parse a JSON configuration document and extract secret keys and flag values.
    """
    raw = json_data.decode("utf-8") if isinstance(json_data, bytes) else json_data
    parsed = json.loads(raw)
    return find_nested_secrets(parsed)
