from __future__ import annotations

import binascii
import json
import struct

from ctf_toolkit.ui.common import print_memory_wrapper, show_text_hex
from ctf_toolkit.utils.io import safe_input, warn
from ctf_toolkit.utils.menu import run_menu


def pwn_calc_menu() -> None:
    from ctf_toolkit.utils.parse import parse_bytes, parse_int

    while True:
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
                show_text_hex(cyclic_create(length), "Pattern")
            elif choice == "3":
                needle_raw = safe_input("Needle (text/hex:...): ").strip()
                needle = parse_bytes(needle_raw, mode="auto")
                max_len = int(safe_input("max_len [default 100000]: ").strip() or "100000")
                print(f"[+] Offset: {cyclic_find(needle, max_len=max_len)}")
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
            show_text_hex(cyclic_create(length), "Pattern")
        except (ValueError, OSError, binascii.Error) as exc:
            warn(f"Error: {exc}")

    def cyclic_find_action() -> None:
        try:
            needle_raw = safe_input("Needle (text/hex:...): ").strip()
            needle = parse_bytes(needle_raw, mode="auto")
            max_len = int(safe_input("max_len [default 100000]: ").strip() or "100000")
            print(f"[+] Offset: {cyclic_find(needle, max_len=max_len)}")
        except (ValueError, OSError, binascii.Error) as exc:
            warn(f"Error: {exc}")

    def pack_unpack_action() -> None:
        try:
            v = parse_int(safe_input("Nilai integer (dec/0x): "))
            p32v = p32(v)
            p64v = p64(v)
            print(f"p32 hex: {p32v.hex()} | u32: {u32(p32v)}")
            print(f"p64 hex: {p64v.hex()} | u64: {u64(p64v)}")
        except (ValueError, OSError, binascii.Error) as exc:
            warn(f"Error: {exc}")

    def elf_triage_action() -> None:
        try:
            path = safe_input("Path ELF: ")
            print(json.dumps(parse_elf(path), indent=2))
        except (ValueError, OSError, binascii.Error) as exc:
            warn(f"Error: {exc}")

    def gadget_scan_action() -> None:
        try:
            path = safe_input("Path binary: ")
            limit = int(safe_input("limit [default 200]: ").strip() or "200")
            data = scan_gadgets(path, limit=limit)
            print(f"ret count: {len(data['ret'])}")
            print(f"ret sample: {[hex(x) for x in data['ret'][:20]]}")
            print(f"pop rdi; ret count: {len(data['pop_rdi_ret'])}")
            print(f"pop rdi; ret sample: {[hex(x) for x in data['pop_rdi_ret'][:20]]}")
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
            print(f"\n[+] Ret2win payload generated ({len(payload)} bytes):")
            print(f"    Raw bytes : {repr(payload)}")
            print(f"    Hex string: {payload.hex()}")
        except Exception as exc:
            warn(f"Error: {exc}")

    def rop_action() -> None:
        try:
            pad = int(safe_input("Offset / Padding length (e.g. 40): "))
            gadgets_raw = safe_input("Gadget addresses separated by comma (hex, e.g. 0x4011d3, 0xdeadc0de, 0x401196): ")
            gadgets = [int(g.strip(), 16) if g.strip().startswith("0x") else int(g.strip()) for g in gadgets_raw.split(",") if g.strip()]
            arch = safe_input("Architecture [x64/x32, default x64]: ").strip().lower() or "x64"
            payload = build_rop_chain(padding_len=pad, gadgets=gadgets, arch=arch)
            print(f"\n[+] ROP chain payload generated ({len(payload)} bytes):")
            print(f"    Raw bytes : {repr(payload)}")
            print(f"    Hex string: {payload.hex()}")
        except Exception as exc:
            warn(f"Error: {exc}")

    def fmt_action() -> None:
        try:
            num = int(safe_input("Number of positional words to probe [default 10]: ").strip() or "10")
            start = int(safe_input("Offset start [default 1]: ").strip() or "1")
            probe = build_format_string_probe(num_words=num, offset_start=start)
            print(f"\n[+] Format string probe string:")
            print(f"    {probe}")
        except Exception as exc:
            warn(f"Error: {exc}")

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
        },
    )
