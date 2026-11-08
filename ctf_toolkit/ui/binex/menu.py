from __future__ import annotations

import binascii
import json
import struct

from ctf_toolkit.ui.common import print_memory_wrapper, show_text_hex
from ctf_toolkit.ui.console import (
    HAS_RICH,
    get_rich_console,
    render_header,
    console_info,
    console_success,
    console_warn,
)
from ctf_toolkit.ui.inspector import inspect_output
from ctf_toolkit.utils.io import safe_input, warn
from ctf_toolkit.utils.menu import run_menu

try:
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
except ImportError:
    pass


def render_stack_frame_diagram(padding_len: int, win_addr: int, arch: str = "x64") -> None:
    """Render an ASCII/Rich visual diagram of the stack layout for buffer overflow & ROP."""
    console = get_rich_console()
    word_size = 8 if arch == "x64" else 4
    total_bytes = padding_len + word_size

    diagram_text = f"""
    [Low Memory / Top of Stack]
    +---------------------------------------------------+  <-- Buffer Start (Offset 0x00)
    |  Payload Buffer Padding: {padding_len} bytes                      |
    |  (e.g. cyclic pattern or cyclic offset)           |
    +---------------------------------------------------+  <-- Offset {padding_len:#x} ({padding_len}d)
    |  Saved Base Pointer ({arch.upper()}: {word_size} bytes)             |
    +---------------------------------------------------+  <-- Offset {padding_len:#x}
    |  Saved Return Address RIP/EIP:                    |
    |  --> Target Function win() [{win_addr:#018x if arch == 'x64' else win_addr:#010x}]  |
    +---------------------------------------------------+  <-- Offset {total_bytes:#x}
    |  16-byte MOVAPS Alignment Check: {'[PASS]' if (padding_len % 16 == 8) else '[WARN: may need ret gadget]'}  |
    +---------------------------------------------------+
    [High Memory / Bottom of Stack]
    """

    if HAS_RICH and console:
        console.print(Panel(diagram_text, title=f"📊 Visual Stack Frame ({arch.upper()})", border_style="cyan"))
    else:
        print(diagram_text)


def pwn_calc_menu() -> None:
    from ctf_toolkit.utils.parse import parse_bytes, parse_int

    while True:
        render_header("BinEx > Pwn & Memory Boundary")
        print("\n=== BinEx > Pwn & Memory Boundary Analyzer ===")
        print("[1] Memory Wrapper (i32/u32/i64/u64)")
        print("[2] De Bruijn Cyclic Create")
        print("[3] De Bruijn Offset Find")
        print("[0] Kembali")
        choice = safe_input("Pilih opsi: ").strip()
        if choice == "0":
            return

        from ctf_toolkit.binex.pwncalc import cyclic_create, cyclic_find, describe_integer_bounds

        try:
            if choice == "1":
                value = parse_int(safe_input("Nilai integer (dec/0x): "))
                limit_raw = safe_input("Batas check (contoh 67) [default 67]: ").strip() or "67"
                limit = int(limit_raw)
                entries = describe_integer_bounds(value, limit=limit)
                print(f"[+] Input: {value} (hex: {value:#x})")
                print_memory_wrapper(entries)
            elif choice == "2":
                length = int(safe_input("Length: "))
                pat = cyclic_create(length)
                inspect_output(pat, title=f"De Bruijn Pattern ({length} bytes)", op_name="cyclic_create")
            elif choice == "3":
                needle_raw = safe_input("Needle (text/hex/0x...): ").strip()
                needle = parse_bytes(needle_raw, mode="auto")
                max_len = int(safe_input("max_len [default 100000]: ").strip() or "100000")
                offset = cyclic_find(needle, max_len=max_len)
                console_success(f"Calculated Offset: {offset} (0x{offset:x})")
                inspect_output({"needle": needle_raw, "offset": offset, "hex_offset": hex(offset)}, title="Cyclic Offset Result", op_name="cyclic_find")
            else:
                warn("Pilihan tidak valid.")
        except (ValueError, binascii.Error) as exc:
            warn(f"Error: {exc}")


def menu() -> None:
    from ctf_toolkit.utils.parse import parse_bytes, parse_int
    from ctf_toolkit.binex.elf import parse_elf
    from ctf_toolkit.binex.gadgets import scan_gadgets
    from ctf_toolkit.binex.pack import p32, p64, u32, u64
    from ctf_toolkit.binex.pwncalc import cyclic_create, cyclic_find
    from ctf_toolkit.binex.pwn_tools import (
        build_format_string_probe,
        build_ret2win_payload,
        build_rop_chain,
        build_variable_overwrite,
    )

    def cyclic_create_action() -> None:
        try:
            length = int(safe_input("Length: "))
            pat = cyclic_create(length)
            inspect_output(pat, title=f"De Bruijn Pattern ({length} bytes)", op_name="cyclic_create")
        except (ValueError, OSError, binascii.Error) as exc:
            warn(f"Error: {exc}")

    def cyclic_find_action() -> None:
        try:
            needle_raw = safe_input("Needle (text/hex:...): ").strip()
            needle = parse_bytes(needle_raw, mode="auto")
            max_len = int(safe_input("max_len [default 100000]: ").strip() or "100000")
            offset = cyclic_find(needle, max_len=max_len)
            console_success(f"Calculated Offset: {offset} (0x{offset:x})")
            inspect_output({"needle": needle_raw, "offset": offset, "hex_offset": hex(offset)}, title="Cyclic Offset Result", op_name="cyclic_find")
        except (ValueError, OSError, binascii.Error) as exc:
            warn(f"Error: {exc}")

    def pack_unpack_action() -> None:
        try:
            v = parse_int(safe_input("Nilai integer (dec/0x): "))
            p32v = p32(v)
            p64v = p64(v)
            print(f"p32 hex: {p32v.hex()} | u32: {u32(p32v)}")
            print(f"p64 hex: {p64v.hex()} | u64: {u64(p64v)}")
            inspect_output({"integer": v, "p32_hex": p32v.hex(), "p64_hex": p64v.hex()}, title="Pack/Unpack", op_name="pack_unpack")
        except (ValueError, OSError, binascii.Error) as exc:
            warn(f"Error: {exc}")

    def elf_triage_action() -> None:
        try:
            path = safe_input("Path ELF: ")
            data = parse_elf(path)
            inspect_output(data, title=f"ELF Triage: {path}", op_name=f"elf_triage:{path}")
        except (ValueError, OSError, binascii.Error) as exc:
            warn(f"Error: {exc}")

    def gadget_scan_action() -> None:
        try:
            path = safe_input("Path binary: ")
            limit = int(safe_input("limit [default 200]: ").strip() or "200")
            data = scan_gadgets(path, limit=limit)
            inspect_output(data, title=f"Gadget Scan: {path}", op_name=f"gadget_scan:{path}")
        except (ValueError, OSError, binascii.Error) as exc:
            warn(f"Error: {exc}")

    def pwn_calc_action() -> None:
        pwn_calc_menu()

    def ret2win_action() -> None:
        try:
            pad = int(safe_input("Offset / Padding length (e.g. 40): "))
            addr_raw = safe_input("Target win() address (hex, e.g. 0x401186): ").strip()
            win_addr = int(addr_raw, 16) if addr_raw.startswith("0x") else int(addr_raw)
            arch = safe_input("Architecture [x64/x32, default x64]: ").strip().lower() or "x64"
            payload = build_ret2win_payload(padding_len=pad, win_addr=win_addr, arch=arch)
            render_stack_frame_diagram(padding_len=pad, win_addr=win_addr, arch=arch)
            inspect_output(payload, title="Ret2Win Payload", op_name="ret2win")
        except Exception as exc:
            warn(f"Error: {exc}")

    def rop_action() -> None:
        try:
            pad = int(safe_input("Offset / Padding length (e.g. 40): "))
            gadgets_raw = safe_input("Gadget addresses separated by comma (hex, e.g. 0x4011d3, 0xdeadc0de): ")
            gadgets = [int(g.strip(), 16) if g.strip().startswith("0x") else int(g.strip()) for g in gadgets_raw.split(",") if g.strip()]
            arch = safe_input("Architecture [x64/x32, default x64]: ").strip().lower() or "x64"
            payload = build_rop_chain(padding_len=pad, gadgets=gadgets, arch=arch)
            inspect_output(payload, title=f"ROP Chain Payload ({len(gadgets)} gadgets)", op_name="rop_chain")
        except Exception as exc:
            warn(f"Error: {exc}")

    def fmt_action() -> None:
        try:
            num = int(safe_input("Number of positional words to probe [default 10]: ").strip() or "10")
            start = int(safe_input("Offset start [default 1]: ").strip() or "1")
            probe = build_format_string_probe(num_words=num, offset_start=start)
            inspect_output(probe, title="Format String Probe String", op_name="format_string_probe")
        except Exception as exc:
            warn(f"Error: {exc}")

    def exploit_template_action() -> None:
        arch = safe_input("Target Architecture [x64/x32, default x64]: ").strip() or "x64"
        host = safe_input("Remote Host [default 127.0.0.1]: ").strip() or "127.0.0.1"
        port = safe_input("Remote Port [default 1337]: ").strip() or "1337"
        binary = safe_input("Local Binary Path [default ./vuln]: ").strip() or "./vuln"

        code = f"""#!/usr/bin/env python3
from pwn import *

# Binary & Context
exe = context.binary = ELF('{binary}', checksec=False)
context.arch = '{arch}'
context.log_level = 'debug'

def start():
    if args.REMOTE:
        return remote('{host}', {port})
    return process([exe.path])

io = start()

# Exploit Payload Construction
padding = 40
payload = flat(
    b'A' * padding,
    # exe.sym['win'],
)

io.sendlineafter(b'> ', payload)
io.interactive()
"""
        inspect_output(code, title="Python Exploit Template (pwntools)", op_name="exploit_template")

    run_menu(
        "BinEx",
        {
            "1": ("Cyclic Pattern Create", cyclic_create_action),
            "2": ("Cyclic Offset Find", cyclic_find_action),
            "3": ("Pack/Unpack (p32/p64/u32/u64)", pack_unpack_action),
            "4": ("ELF Triage / Checksec-lite", elf_triage_action),
            "5": ("Gadget Scan (ret, pop rdi; ret)", gadget_scan_action),
            "6": ("Pwn & Memory Boundary Analyzer", pwn_calc_action),
            "7": ("Ret2win Payload Crafter", ret2win_action),
            "8": ("ROP Chain Crafter", rop_action),
            "9": ("Format String Probe Generator", fmt_action),
            "10": ("Exploit Template Generator (pwntools boilerplate)", exploit_template_action),
        },
    )
