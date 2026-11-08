from __future__ import annotations

import re
from typing import Any

WASM_SECTION_NAMES: dict[int, str] = {
    0: "Custom",
    1: "Type",
    2: "Import",
    3: "Function",
    4: "Table",
    5: "Memory",
    6: "Global",
    7: "Export",
    8: "Start",
    9: "Element",
    10: "Code",
    11: "Data",
    12: "DataCount",
}


def _read_uleb128(data: bytes, idx: int) -> tuple[int, int]:
    res = 0
    shift = 0
    while idx < len(data):
        b = data[idx]
        idx += 1
        res |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return res, idx


def analyze_wasm_binary(wasm_bytes: bytes) -> dict[str, Any]:
    """
    Dissect a WebAssembly (`.wasm`) binary module: verify magic (`\\x00asm`) and version,
    enumerate sections, parse Export section symbol names, and extract printable strings from Data segments.
    """
    if len(wasm_bytes) < 8 or wasm_bytes[:4] != b"\x00asm":
        raise ValueError("Invalid WebAssembly magic header (expected \\x00asm)")

    version = int.from_bytes(wasm_bytes[4:8], "little")
    idx = 8
    sections: list[dict[str, Any]] = []
    exports: list[str] = []
    data_strings: list[str] = []

    while idx < len(wasm_bytes):
        sec_id = wasm_bytes[idx]
        idx += 1
        sec_len, idx = _read_uleb128(wasm_bytes, idx)
        sec_body = wasm_bytes[idx : idx + sec_len]
        idx += sec_len

        sec_name = WASM_SECTION_NAMES.get(sec_id, f"Unknown({sec_id})")
        sections.append({"id": sec_id, "name": sec_name, "size": sec_len})

        if sec_id == 7 and sec_body:
            # Parse Export section
            p = 0
            count, p = _read_uleb128(sec_body, p)
            for _ in range(count):
                if p >= len(sec_body):
                    break
                name_len, p = _read_uleb128(sec_body, p)
                exp_name = sec_body[p : p + name_len].decode("utf-8", errors="ignore")
                p += name_len
                if p < len(sec_body):
                    p += 1  # export kind
                    _, p = _read_uleb128(sec_body, p)
                exports.append(exp_name)
        elif sec_id == 11 and sec_body:
            for m in re.findall(rb"[ -~]{4,}", sec_body):
                s = m.decode("latin-1")
                if s not in data_strings:
                    data_strings.append(s)

    all_strings = [m.decode("latin-1") for m in re.findall(rb"[ -~]{4,}", wasm_bytes)]
    return {
        "version": version,
        "sections": sections,
        "exports": exports,
        "data_strings": data_strings or all_strings,
    }
