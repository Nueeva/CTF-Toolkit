from __future__ import annotations

from pathlib import Path


def find_ret_offsets(data: bytes, limit: int = 500) -> list[int]:
    hits: list[int] = []
    idx = 0
    while len(hits) < limit:
        idx = data.find(b"\xC3", idx)
        if idx == -1:
            break
        hits.append(idx)
        idx += 1
    return hits


def find_pop_rdi_ret_offsets(data: bytes, limit: int = 500) -> list[int]:
    hits: list[int] = []
    idx = 0
    pattern = b"\x5f\xc3"
    while len(hits) < limit:
        idx = data.find(pattern, idx)
        if idx == -1:
            break
        hits.append(idx)
        idx += 1
    return hits


def scan_gadgets(path: str, limit: int = 200) -> dict[str, list[int]]:
    data = Path(path).read_bytes()
    return {
        "ret": find_ret_offsets(data, limit=limit),
        "pop_rdi_ret": find_pop_rdi_ret_offsets(data, limit=limit),
    }
