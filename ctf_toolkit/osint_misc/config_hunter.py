from __future__ import annotations

import csv
import io
import json
import os
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

def extract_html_table_secrets(html_content: str, pattern: str = r"GETSFLAG\{[^}]+\}") -> list[dict[str, str]]:
    """
    Parse HTML report tables and extract secrets/flags from table cell contents with row/column index metadata.
    """
    results: list[dict[str, str]] = []
    regex = re.compile(pattern)

    # Extract all rows from <tr> tags
    rows = re.findall(r"<tr[^>]*>(.*?)</tr>", html_content, re.DOTALL | re.IGNORECASE)
    for row_idx, row in enumerate(rows):
        cells = re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", row, re.DOTALL | re.IGNORECASE)
        for col_idx, cell in enumerate(cells):
            # Clean cell text tags
            cell_text = re.sub(r"<[^>]+>", "", cell).strip()
            m = regex.search(cell_text)
            if m:
                results.append({
                    "row": str(row_idx),
                    "col": str(col_idx),
                    "secret": m.group(0),
                    "cell_text": cell_text,
                })
    return results

def parse_properties(text: str) -> dict[str, str]:
    """
    Parse Java .properties configuration file content into key-value dictionary.
    Handles # and ! comments, escaping, and : or = delimiters.
    """
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        # Find first delimiter (= or :)
        delim_idx = -1
        for idx, ch in enumerate(line):
            if ch in ("=", ":"):
                delim_idx = idx
                break
        if delim_idx != -1:
            key = line[:delim_idx].strip()
            val = line[delim_idx + 1:].strip()
            out[key] = val
        else:
            out[line] = ""
    return out


def parse_markdown_table(text: str) -> list[dict[str, str]]:
    """
    Parse GitHub Flavored Markdown table into a list of row dictionaries.
    """
    lines = [line.strip() for line in text.splitlines() if line.strip().startswith("|")]
    if len(lines) < 2:
        return []

    # Extract headers
    headers = [col.strip() for col in lines[0].strip("|").split("|")]
    
    rows: list[dict[str, str]] = []
    # Line 1 is typically separator (|---|---|)
    start_row = 1
    if len(lines) > 1 and all(c in "-: |" for c in lines[1]):
        start_row = 2

    for line in lines[start_row:]:
        cols = [col.strip() for col in line.strip("|").split("|")]
        row_dict = {}
        for h, c in zip(headers, cols):
            row_dict[h] = c
        if row_dict:
            rows.append(row_dict)

    return rows

def parse_vcf(vcf_text: str) -> list[dict[str, str]]:
    """
    Parse vCard (.vcf) formatted text into a list of contact card dictionaries.
    """
    cards: list[dict[str, str]] = []
    current: dict[str, str] = {}
    in_card = False

    for line in vcf_text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.upper() == "BEGIN:VCARD":
            in_card = True
            current = {}
        elif line.upper() == "END:VCARD":
            if in_card and current:
                cards.append(current)
            in_card = False
            current = {}
        elif in_card and ":" in line:
            key, val = line.split(":", 1)
            current[key.strip()] = val.strip()

    return cards


def parse_ics(ics_text: str) -> list[dict[str, str]]:
    """
    Parse iCalendar (.ics) formatted text into a list of event dictionaries.
    """
    events: list[dict[str, str]] = []
    current: dict[str, str] = {}
    in_event = False

    for line in ics_text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.upper() == "BEGIN:VEVENT":
            in_event = True
            current = {}
        elif line.upper() == "END:VEVENT":
            if in_event and current:
                events.append(current)
            in_event = False
            current = {}
        elif in_event and ":" in line:
            key, val = line.split(":", 1)
            current[key.strip()] = val.strip()

    return events





def extract_cron_secrets(text: str) -> list[str]:
    """Extract potential secrets, commands, and base64 payloads from crontab lines."""
    secrets: list[str] = []
    lines = text.strip().splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Base64 encoded strings
        b64_matches = re.findall(r"(?:echo|base64\s+-d|b64decode)\s+['\"]?([A-Za-z0-9+/=]{8,})", line)
        for b in b64_matches:
            secrets.append(b)
        # Tokens, flags, keys
        token_matches = re.findall(r"(?:token|key|secret|password|flag)=([^\s;&]+)", line, re.IGNORECASE)
        for t in token_matches:
            secrets.append(t)
        # Flag patterns
        flag_matches = re.findall(r"[A-Za-z0-9_]+{[^}]+}", line)
        for f in flag_matches:
            secrets.append(f)
    return secrets


def extract_sqlite_secrets(db_path_or_bytes: str | bytes | Any, keywords: list[str] | None = None) -> list[str]:
    """Inspect an SQLite database for secret-bearing values across all tables and text columns."""
    import sqlite3
    import tempfile
    from pathlib import Path

    if keywords is None:
        keywords = ["flag", "token", "key", "secret", "password", "hash", "auth", "root"]

    results: list[str] = []
    tmp_path = None
    if isinstance(db_path_or_bytes, bytes):
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        tmp.write(db_path_or_bytes)
        tmp.close()
        db_path = tmp.name
        tmp_path = tmp.name
    else:
        db_path = str(db_path_or_bytes)

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall() if not row[0].startswith("sqlite_")]

        for table in tables:
            try:
                cursor.execute(f"PRAGMA table_info({table});")
                cols = [col[1] for col in cursor.fetchall()]
                cursor.execute(f"SELECT * FROM {table};")
                rows = cursor.fetchall()
                for row in rows:
                    for i, val in enumerate(row):
                        val_str = str(val)
                        col_name = cols[i].lower() if i < len(cols) else ""
                        if any(kw in col_name for kw in keywords) or any(kw in val_str.lower() for kw in keywords) or "{" in val_str:
                            results.append(val_str)
            except Exception:
                continue
        conn.close()
    except Exception:
        pass
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass

    return results


def _fallback_parse_toml(toml_text: str) -> dict[str, Any]:
    root: dict[str, Any] = {}
    curr: dict[str, Any] = root
    for raw_line in toml_text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            sec_path = line[1:-1].strip().split(".")
            curr = root
            for part in sec_path:
                part = part.strip().strip('"').strip("'")
                curr = curr.setdefault(part, {})
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            key = k.strip().strip('"').strip("'")
            val_str = v.strip()
            if (val_str.startswith('"') and val_str.endswith('"')) or (
                val_str.startswith("'") and val_str.endswith("'")
            ):
                val: Any = val_str[1:-1]
            elif val_str.lower() in ("true", "false"):
                val = val_str.lower() == "true"
            else:
                try:
                    val = int(val_str)
                except ValueError:
                    val = val_str
            curr[key] = val
    return root


def parse_toml_secrets(toml_text: str) -> dict[str, Any]:
    """Parse TOML configuration text using tomllib / tomli / fallback and extract nested secrets."""
    try:
        import tomllib
        data = tomllib.loads(toml_text)
    except ImportError:
        try:
            import tomli as tomllib
            data = tomllib.loads(toml_text)
        except ImportError:
            data = _fallback_parse_toml(toml_text)
    return {"parsed": data, "secrets": find_nested_secrets(data)}


def parse_jsonc(jsonc_text: str) -> Any:
    """Strip `//` and `/* ... */` comments and trailing commas from JSONC text and parse as JSON."""
    import json
    import re

    no_block = re.sub(r"/\*.*?\*/", "", jsonc_text, flags=re.DOTALL)
    lines = []
    for line in no_block.splitlines():
        in_str = False
        escaped = False
        cut_idx = len(line)
        for i, ch in enumerate(line):
            if escaped:
                escaped = False
                continue
            if ch == "\\":
                escaped = True
                continue
            if ch == '"':
                in_str = not in_str
            elif not in_str and line[i : i + 2] == "//":
                cut_idx = i
                break
        lines.append(line[:cut_idx])
    cleaned = "\n".join(lines)
    cleaned = re.sub(r",\s*([\]}])", r"\1", cleaned)
    return json.loads(cleaned)


def resolve_json_pointer(doc: Any, pointer: str) -> Any:
    """Resolve an RFC 6901 JSON Pointer (e.g. `/a/b/0`) against a parsed JSON document."""
    if not pointer or pointer == "/":
        return doc
    parts = pointer.lstrip("/").split("/")
    curr = doc
    for raw_part in parts:
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(curr, list):
            curr = curr[int(part)]
        elif isinstance(curr, dict):
            curr = curr[part]
        else:
            raise KeyError(f"Cannot traverse {part} on non-container")
    return curr


def parse_mime_email_parts(eml_source: str | bytes) -> dict[str, Any]:
    """Parse RFC 822 / MIME `.eml` message headers, decoded body parts, and attachment payloads."""
    from email import policy
    from email.parser import BytesParser

    raw = eml_source.encode("utf-8") if isinstance(eml_source, str) else eml_source
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    headers = {k: str(v) for k, v in msg.items()}
    bodies: list[str] = []
    attachments: list[dict[str, Any]] = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            fn = part.get_filename()
            payload = part.get_payload(decode=True) or b""
            if fn:
                attachments.append({"filename": fn, "data": payload})
            else:
                bodies.append(payload.decode("utf-8", errors="replace"))
    else:
        payload = msg.get_payload(decode=True) or b""
        bodies.append(payload.decode("utf-8", errors="replace"))

    return {"headers": headers, "bodies": bodies, "attachments": attachments}


def extract_xml_namespaced_values(xml_text: str) -> list[str]:
    """Extract all element text values and attribute values from XML (including namespaced tags)."""
    import xml.etree.ElementTree as ET

    root = ET.fromstring(xml_text)
    values: list[str] = []
    for elem in root.iter():
        if elem.text and elem.text.strip():
            values.append(elem.text.strip())
        for attr_val in elem.attrib.values():
            if attr_val and attr_val.strip():
                values.append(attr_val.strip())
    return values
