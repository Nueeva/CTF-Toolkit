from __future__ import annotations

import base64
import hashlib


def parse_id_range(raw: str) -> tuple[int, int]:
    text = raw.strip()
    if not text:
        raise ValueError("ID kosong")
    if "-" in text:
        start_text, end_text = text.split("-", 1)
        start = int(start_text.strip())
        end = int(end_text.strip())
        return start, end
    value = int(text)
    return value, value


def iter_id_values(start: int, end: int):
    step = 1 if end >= start else -1
    value = start
    while True:
        yield value
        if value == end:
            break
        value += step


def range_count(start: int, end: int) -> int:
    return abs(end - start) + 1


def default_padding_widths(max_value: int) -> list[int]:
    base = max(1, len(str(abs(max_value))))
    return [base, base + 1, base + 2]


def parse_padding_widths(raw: str, defaults: list[int]) -> list[int]:
    text = raw.strip()
    if not text:
        return defaults
    widths = []
    for token in text.split(","):
        token = token.strip()
        if not token:
            continue
        width = int(token)
        if width <= 0:
            continue
        widths.append(width)
    return sorted(set(widths)) or defaults


def build_idor_payloads(value: int, widths: list[int]) -> list[dict[str, str]]:
    raw_value = str(value)
    raw_data = raw_value.encode("utf-8")
    min_len = len(raw_value.lstrip("-"))
    payloads: list[dict[str, str]] = []
    for width in widths:
        if width < min_len:
            continue
        padded = raw_value.zfill(width)
        data = padded.encode("utf-8")
        payloads.append(
            {
                "raw": raw_value,
                "raw_base64": base64.b64encode(raw_data).decode("utf-8"),
                "raw_md5": hashlib.md5(raw_data).hexdigest(),
                "raw_hex": raw_data.hex(),
                "padded": padded,
                "padded_base64": base64.b64encode(data).decode("utf-8"),
                "padded_md5": hashlib.md5(data).hexdigest(),
                "padded_hex": data.hex(),
            }
        )
    return payloads
