from __future__ import annotations

import base64
import hmac
import os
import re
from typing import Any

from ctf_toolkit.utils.io import error

SUSPICIOUS_KEYWORDS = ["flag", "ctf", "key", "lks", "lksjaktim", "password", "secret", "token", "admin"]
XOR_SEARCH_KEYWORDS = ["flag", "ctf", "key", "lks", "lksjaktim"]
MAX_SUSPICIOUS_DISPLAY = 100
MAX_RESPONSE_DISPLAY = 4000


def parse_params(param_text: str) -> dict[str, str]:
    params: dict[str, str] = {}
    if not param_text.strip():
        return params
    for pair in param_text.split(","):
        pair = pair.strip()
        if not pair:
            continue
        if "=" not in pair:
            error(f"Lewati parameter tidak valid: {pair}")
            continue
        key, value = pair.split("=", 1)
        params[key.strip()] = value.strip()
    return params


def sanitize_params(params: dict[str, str]) -> dict[str, str]:
    clean: dict[str, str] = {}
    for key, value in params.items():
        if not re.match(r"^[A-Za-z0-9_.\-\[\]]{1,100}$", key):
            error(f"Lewati key parameter tidak valid: {key}")
            continue
        safe_value = re.sub(r"[\x00-\x1F\x7F]", "", str(value))[:500]
        clean[key] = safe_value
    return clean


def validate_http_url(url: str) -> bool:
    return re.match(r"^https?://", url, flags=re.IGNORECASE) is not None


def xor_bytes(data_bytes: bytes, key: int) -> bytes:
    return bytes(byte ^ key for byte in data_bytes)


def xor_with_repeating_key(data_bytes: bytes, key_bytes: bytes) -> bytes:
    if not key_bytes:
        raise ValueError("key pattern tidak boleh kosong")
    return bytes(data_bytes[idx] ^ key_bytes[idx % len(key_bytes)] for idx in range(len(data_bytes)))


def looks_like_byte_list(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    lowered = stripped.lower()
    if "0x" in lowered:
        return True
    return "," in stripped and bool(re.search(r"\d", stripped))


def int_to_bytes(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    size = (value.bit_length() + 7) // 8
    return value.to_bytes(size, "big")


def show_text_hex(data: bytes, title: str = "Hasil") -> None:
    print(f"[+] {title} (hex): {data.hex()}")
    print(f"[+] {title} (text): {data.decode('utf-8', errors='ignore')}")


def print_table(headers: list[str], rows: list[list[str]]) -> None:
    widths = [len(header) for header in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))
    header_line = " | ".join(header.ljust(widths[idx]) for idx, header in enumerate(headers))
    print(header_line)
    print("-" * len(header_line))
    for row in rows:
        print(" | ".join(cell.ljust(widths[idx]) for idx, cell in enumerate(row)))


def extract_lks_flag_candidates(text: str) -> list[str]:
    patterns = [
        r"LKS\{[^\n\r\}]{1,300}\}",
        r"LKSJAKTIM\{[^\n\r\}]{1,300}\}",
        r"LKS[-_\s]?JAKTIM\{[^\n\r\}]{1,300}\}",
    ]
    found: set[str] = set()
    for pattern in patterns:
        found.update(re.findall(pattern, text, flags=re.IGNORECASE))
    return sorted(found)


def print_lks_flag_candidates_from_text(text: str) -> None:
    flags = extract_lks_flag_candidates(text)
    if flags:
        print("[+] Kandidat flag LKS/LKSJAKTIM:")
        for idx, flag in enumerate(flags, start=1):
            print(f"  {idx}. {flag}")
    else:
        print("[-] Pola flag LKS/LKSJAKTIM belum terdeteksi.")


def print_memory_wrapper(entries: list[dict[str, Any]]) -> None:
    rows: list[list[str]] = []
    for entry in entries:
        status = "ok"
        if entry["overflow"]:
            status = "overflow"
        elif entry["underflow"]:
            status = "underflow"
        bypass = "YES" if entry.get("bypass_check") else "-"
        rows.append(
            [
                str(entry["label"]),
                str(entry["value"]),
                str(entry["hex"]),
                f"{entry['min']}..{entry['max']}",
                status,
                bypass,
            ]
        )
    print_table(["type", "value", "hex", "range", "status", "bypass>limit"], rows)
    if any(entry.get("bypass_check") for entry in entries):
        limit = entries[0].get("limit", 67)
        print(f"[!] Potensi bypass check 'if (size > {limit})' karena underflow.")


def read_byte_value(label: str, safe_input_fn) -> int:
    from ctf_toolkit.utils.parse import parse_int

    value = parse_int(safe_input_fn(f"{label} (0-255, dec/0x): ").strip())
    if not 0 <= value <= 255:
        raise ValueError(f"{label} harus 0..255")
    return value


def read_xor_input_data(safe_input_fn, read_bytes_file_fn) -> bytes:
    from ctf_toolkit.utils.parse import parse_byte_list

    mode = safe_input_fn("Input [1] teks / [2] file: ").strip()
    if mode == "1":
        raw = safe_input_fn("Masukkan data/ciphertext: ")
        if looks_like_byte_list(raw):
            return parse_byte_list(raw)
        return raw.encode("utf-8", errors="ignore")
    if mode == "2":
        path = safe_input_fn("Masukkan path file: ").strip()
        return read_bytes_file_fn(path)
    raise ValueError("pilihan input tidak valid")


def read_bytes_prompt(label: str, safe_input_fn) -> bytes:
    from ctf_toolkit.utils.parse import parse_bytes

    raw = safe_input_fn(f"{label} (prefix hex:/b64:/raw:, default auto): ")
    return parse_bytes(raw, mode="auto")


def dummy_login(password: str) -> bool:
    """Simulation-only credential check for CTF labs; never use for real authentication."""
    correct_password = os.getenv("DUMMY_LOGIN_PASSWORD", "ctf123")
    return hmac.compare_digest(password, correct_password)


def b64_encode_text(text: str) -> str:
    return base64.b64encode(text.encode()).decode()
