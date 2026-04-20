from __future__ import annotations

import struct
from pathlib import Path

ELF_MAGIC = b"\x7fELF"
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PT_DYNAMIC = 2
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1

MACHINE_MAP = {
    0x03: "x86",
    0x3E: "x86_64",
    0x28: "ARM",
    0xB7: "AArch64",
    0x08: "MIPS",
}


def _fmt(endian: str, code: str) -> str:
    return ("<" if endian == "little" else ">") + code


def parse_elf(path: str) -> dict[str, object]:
    data = Path(path).read_bytes()
    if len(data) < 0x40 or data[:4] != ELF_MAGIC:
        raise ValueError("not an ELF file")

    ei_class = data[4]
    ei_data = data[5]
    bits = 64 if ei_class == 2 else 32 if ei_class == 1 else 0
    endian = "little" if ei_data == 1 else "big" if ei_data == 2 else "unknown"
    if bits == 0 or endian == "unknown":
        raise ValueError("unsupported ELF format")

    if bits == 64:
        e_type, e_machine = struct.unpack_from(_fmt(endian, "HH"), data, 16)
        e_entry = struct.unpack_from(_fmt(endian, "Q"), data, 24)[0]
        e_phoff = struct.unpack_from(_fmt(endian, "Q"), data, 32)[0]
        e_phentsize, e_phnum = struct.unpack_from(_fmt(endian, "HH"), data, 54)
    else:
        e_type, e_machine = struct.unpack_from(_fmt(endian, "HH"), data, 16)
        e_entry = struct.unpack_from(_fmt(endian, "I"), data, 24)[0]
        e_phoff = struct.unpack_from(_fmt(endian, "I"), data, 28)[0]
        e_phentsize, e_phnum = struct.unpack_from(_fmt(endian, "HH"), data, 42)

    phdrs: list[dict[str, int]] = []
    for idx in range(e_phnum):
        off = e_phoff + idx * e_phentsize
        if off + e_phentsize > len(data):
            raise ValueError("malformed ELF: program header exceeds file bounds")
        if bits == 64:
            p_type = struct.unpack_from(_fmt(endian, "I"), data, off)[0]
            p_flags = struct.unpack_from(_fmt(endian, "I"), data, off + 4)[0]
            p_offset = struct.unpack_from(_fmt(endian, "Q"), data, off + 8)[0]
            p_filesz = struct.unpack_from(_fmt(endian, "Q"), data, off + 32)[0]
        else:
            p_type = struct.unpack_from(_fmt(endian, "I"), data, off)[0]
            p_offset = struct.unpack_from(_fmt(endian, "I"), data, off + 4)[0]
            p_filesz = struct.unpack_from(_fmt(endian, "I"), data, off + 16)[0]
            p_flags = struct.unpack_from(_fmt(endian, "I"), data, off + 24)[0]
        phdrs.append(
            {
                "type": p_type,
                "flags": p_flags,
                "offset": p_offset,
                "filesz": p_filesz,
            }
        )

    relro = any(p["type"] == PT_GNU_RELRO for p in phdrs)
    nx = None
    for p in phdrs:
        if p["type"] == PT_GNU_STACK:
            nx = (p["flags"] & 0x1) == 0
            break

    bind_now = False
    for p in phdrs:
        if p["type"] != PT_DYNAMIC:
            continue
        start = p["offset"]
        end = start + p["filesz"]
        step = 16 if bits == 64 else 8
        tag_fmt = "qQ" if bits == 64 else "iI"
        upper = min(end, len(data))
        for dyn_off in range(start, upper, step):
            if dyn_off + step > len(data):
                break
            tag, val = struct.unpack_from(_fmt(endian, tag_fmt), data, dyn_off)
            if tag == 0:
                break
            if tag == DT_BIND_NOW:
                bind_now = True
            elif tag == DT_FLAGS and (val & DF_BIND_NOW):
                bind_now = True
            elif tag == DT_FLAGS_1 and (val & DF_1_NOW):
                bind_now = True

    canary = b"__stack_chk_fail" in data

    relro_state = "No RELRO"
    if relro and bind_now:
        relro_state = "Full RELRO"
    elif relro:
        relro_state = "Partial RELRO"

    return {
        "is_elf": True,
        "bits": bits,
        "endian": endian,
        "e_machine": MACHINE_MAP.get(e_machine, f"unknown(0x{e_machine:x})"),
        "entry": e_entry,
        "pie": e_type == 3,
        "nx": nx,
        "relro": relro_state,
        "canary_heuristic": canary,
    }
