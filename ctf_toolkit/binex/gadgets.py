from __future__ import annotations

from pathlib import Path

GADGET_PATTERNS: dict[str, bytes] = {
    "ret": b"\xc3",
    "pop_rdi_ret": b"\x5f\xc3",
    "pop_rsi_ret": b"\x5e\xc3",
    "pop_rsi_r15_ret": b"\x5e\x41\x5f\xc3",
    "pop_rdx_ret": b"\x5a\xc3",
    "pop_rax_ret": b"\x58\xc3",
    "pop_rbx_ret": b"\x5b\xc3",
    "pop_rcx_ret": b"\x59\xc3",
    "pop_rbp_ret": b"\x5d\xc3",
    "pop_rsp_ret": b"\x5c\xc3",
    "leave_ret": b"\xc9\xc3",
    "syscall": b"\x0f\x05",
    "syscall_ret": b"\x0f\x05\xc3",
    "int_0x80": b"\xcd\x80",
    "int_0x80_ret": b"\xcd\x80\xc3",
    "jmp_rax": b"\xff\xe0",
    "call_rax": b"\xff\xd0",
    "jmp_rsp": b"\xff\xe4",
    "call_rsp": b"\xff\xd4",
    "jmp_rdi": b"\xff\xe7",
    "call_rdi": b"\xff\xd7",
    "jmp_rsi": b"\xff\xe6",
    "call_rsi": b"\xff\xd6",
    "nop_ret": b"\x90\xc3",
    "xchg_eax_esp_ret": b"\x94\xc3",
    "pop_eax_ret": b"\x58\xc3",
    "pop_ebx_ret": b"\x5b\xc3",
    "pop_ecx_ret": b"\x59\xc3",
    "pop_edx_ret": b"\x5a\xc3",
}


def find_gadget_offsets(data: bytes, pattern: bytes, limit: int = 500) -> list[int]:
    hits: list[int] = []
    idx = 0
    while len(hits) < limit:
        idx = data.find(pattern, idx)
        if idx == -1:
            break
        hits.append(idx)
        idx += 1
    return hits


def find_ret_offsets(data: bytes, limit: int = 500) -> list[int]:
    return find_gadget_offsets(data, b"\xc3", limit=limit)


def find_pop_rdi_ret_offsets(data: bytes, limit: int = 500) -> list[int]:
    return find_gadget_offsets(data, b"\x5f\xc3", limit=limit)


def scan_gadgets(path: str, limit: int = 200) -> dict[str, list[int]]:
    data = Path(path).read_bytes()
    results: dict[str, list[int]] = {}
    for name, pat in GADGET_PATTERNS.items():
        matches = find_gadget_offsets(data, pat, limit=limit)
        if matches or name in ("ret", "pop_rdi_ret"):
            results[name] = matches
    return results
