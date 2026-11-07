from __future__ import annotations

import csv
import io
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

def extract_ini_secrets(ini_data: str | bytes) -> list[tuple[str, str]]:
    """
    Parse an INI / CFG configuration document and extract secret keys, credentials,
    and flag patterns across all sections.
    """
    import configparser

    cp = configparser.ConfigParser()
    raw = ini_data.decode("utf-8") if isinstance(ini_data, bytes) else ini_data
    cp.read_string(raw)

    keywords = ["secret", "key", "token", "password", "pass", "flag", "auth", "cred"]
    findings: list[tuple[str, str]] = []

    for section in cp.sections():
        for k, v in cp.items(section):
            curr_path = f"{section}.{k}"
            k_lower = k.lower()
            if any(kw in k_lower for kw in keywords):
                findings.append((curr_path, v))
            elif re.search(r"(?:GETSFLAG|FLAG|CTF)\{[^}]+\}", v):
                findings.append((curr_path, v))

    return findings

def extract_csv_secrets(csv_data: str | bytes) -> list[tuple[str, str]]:
    """
    Parse a CSV table and extract cells containing flag patterns or sensitive credentials.
    Returns list of (row_col_info, cell_value).
    """
    import csv
    import io

    raw = csv_data.decode("utf-8") if isinstance(csv_data, bytes) else csv_data
    reader = csv.reader(io.StringIO(raw))
    findings: list[tuple[str, str]] = []
    header = None

    for row_idx, row in enumerate(reader):
        if row_idx == 0 and not any("GETSFLAG" in cell for cell in row):
            header = row
            continue
        for col_idx, cell in enumerate(row):
            col_name = header[col_idx] if header and col_idx < len(header) else f"col_{col_idx}"
            curr_path = f"row_{row_idx}.{col_name}"
            if re.search(r"(?:GETSFLAG|FLAG|CTF)\{[^}]+\}", cell):
                findings.append((curr_path, cell))
            elif any(kw in cell.lower() for kw in ["secret", "token", "password"]):
                findings.append((curr_path, cell))

    return findings

def extract_tsv_secrets(content: str, pattern: str = r"GETSFLAG\{[^}]+\}") -> list[dict[str, str]]:
    """
    Scan a TSV (tab-separated values) document for secrets, flags, or suspicious fields.
    Returns a list of dicts with row, column, header, and matched value.
    """
    results: list[dict[str, str]] = []
    regex = re.compile(pattern)

    reader = csv.reader(io.StringIO(content), delimiter="\t")
    rows = list(reader)
    if not rows:
        return results

    headers = rows[0] if rows else []

    for row_idx, row in enumerate(rows):
        for col_idx, cell in enumerate(row):
            m = regex.search(cell)
            if m:
                header_name = headers[col_idx] if col_idx < len(headers) else f"col_{col_idx}"
                results.append({
                    "row": str(row_idx),
                    "col": str(col_idx),
                    "header": header_name,
                    "secret": m.group(0),
                    "raw_cell": cell,
                })
    return results

def extract_jsonl_secrets(content: str, pattern: str = r"GETSFLAG\{[^}]+\}") -> list[dict[str, str]]:
    """
    Scan a JSON Lines (.jsonl) document line by line for secrets or flags.
    """
    results: list[dict[str, str]] = []
    regex = re.compile(pattern)

    for line_idx, line in enumerate(content.splitlines()):
        line_clean = line.strip()
        if not line_clean:
            continue
        try:
            obj = json.loads(line_clean)
            nested = find_nested_secrets(obj, pattern=pattern)
            for path_str, val in nested:
                results.append({
                    "line": str(line_idx + 1),
                    "path": path_str,
                    "secret": val,
                })
        except Exception:
            m = regex.search(line_clean)
            if m:
                results.append({
                    "line": str(line_idx + 1),
                    "path": "raw_line",
                    "secret": m.group(0),
                })
    return results

