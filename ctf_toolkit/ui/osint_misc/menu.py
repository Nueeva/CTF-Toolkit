from __future__ import annotations

import os

from ctf_toolkit.osint_misc.bencode import parse_torrent
from ctf_toolkit.osint_misc.binary_formats import (
    decode_cbor_raw,
    decode_msgpack_raw,
    decode_protobuf_raw,
    parse_asn1_der_strings,
)
from ctf_toolkit.osint_misc.config_hunter import (
    extract_csv_secrets,
    extract_ini_secrets,
    extract_json_secrets,
    extract_yaml_secrets,
)
from ctf_toolkit.osint_misc.esolang import (
    brainfuck_eval,
    deadfish_eval,
    eval_stack_vm,
    ook_eval,
    spoon_eval,
    whitespace_eval,
)
from ctf_toolkit.osint_misc.rpn import eval_rpn_tape
from ctf_toolkit.osint_misc.stego import (
    decode_seven_segment,
    decode_trailing_whitespace,
    decode_unicode_tag_plane,
    decode_zero_width,
    extract_acrostic,
)
from ctf_toolkit.ui.console import render_header, render_menu_panel
from ctf_toolkit.ui.inspector import inspect_output
from ctf_toolkit.ui.session import resolve_smart_input
from ctf_toolkit.utils.io import read_bytes_file, read_text_file, safe_input, warn


def menu() -> None:
    from ctf_toolkit.main_cli import handle_global_hotkey

    items = [
        ("1", "Brainfuck Interpreter"),
        ("2", "Ook! Interpreter"),
        ("3", "Torrent / Bencode Metadata Extractor"),
        ("4", "Esoteric Suite (Deadfish / Spoon / Whitespace / Stack VM)"),
        ("5", "RPN (Reverse Polish Notation) Tape Evaluator"),
        ("6", "Text Stego (Zero-Width / Tag Plane / Trailing Whitespace / Acrostic / 7-Segment)"),
        ("7", "Config & Secret Hunter (JSON / YAML / INI / CSV)"),
        ("8", "Binary Wire Formats (Protobuf / MessagePack / CBOR / ASN.1 DER)"),
        ("0", "Kembali"),
    ]

    while True:
        render_header("OSINT, Steganography & Miscellaneous")
        render_menu_panel("OSINT & Misc Workbench", items)
        choice = safe_input("Pilih opsi: ").strip()
        if choice == "0":
            return
        if handle_global_hotkey(choice):
            continue

        if choice == "1":
            mode = safe_input("Input via [1] Teks langsung / [2] Path file: ").strip()
            src = read_text_file(safe_input("Path file .bf: ").strip()) if mode == "2" else safe_input("Source code: ").strip()
            if not src:
                warn("Source code kosong.")
                continue
            inp = safe_input("Input runtime [opsional]: ").strip()
            try:
                inspect_output(brainfuck_eval(src, inp), title="Brainfuck Output", op_name="brainfuck_eval")
            except Exception as e:
                warn(f"Error eksekusi: {e}")

        elif choice == "2":
            mode = safe_input("Input via [1] Teks langsung / [2] Path file: ").strip()
            src = read_text_file(safe_input("Path file .ook: ").strip()) if mode == "2" else safe_input("Source code: ").strip()
            if not src:
                warn("Source code kosong.")
                continue
            inp = safe_input("Input runtime [opsional]: ").strip()
            try:
                inspect_output(ook_eval(src, inp), title="Ook! Output", op_name="ook_eval")
            except Exception as e:
                warn(f"Error eksekusi: {e}")

        elif choice == "3":
            p = safe_input("Path file .torrent: ").strip()
            if not os.path.exists(p):
                warn("File tidak ditemukan.")
                continue
            try:
                data = read_bytes_file(p)
                meta = parse_torrent(data)
                inspect_output(meta, title="Torrent Metadata", op_name="parse_torrent")
            except Exception as e:
                warn(f"Error parsing torrent: {e}")

        elif choice == "4":
            print("[1] Deadfish  [2] Spoon  [3] Whitespace  [4] Mini Stack VM")
            sub = safe_input("Pilih interpreter [1-4]: ").strip()
            src = str(resolve_smart_input(safe_input("Source / @file: ").strip(), as_bytes=False))
            if sub == "1":
                inspect_output(deadfish_eval(src), title="Deadfish Output", op_name="deadfish_eval")
            elif sub == "2":
                inspect_output(spoon_eval(src), title="Spoon Output", op_name="spoon_eval")
            elif sub == "3":
                inspect_output(whitespace_eval(src), title="Whitespace Output", op_name="whitespace_eval")
            elif sub == "4":
                inspect_output(eval_stack_vm(src), title="Stack VM Output", op_name="eval_stack_vm")

        elif choice == "5":
            src = str(resolve_smart_input(safe_input("RPN tape lines / @file: ").strip(), as_bytes=False))
            inspect_output(eval_rpn_tape(src.splitlines()), title="RPN Tape Result", op_name="eval_rpn_tape")

        elif choice == "6":
            print("[1] Zero-Width  [2] Unicode Tag Plane  [3] Trailing Whitespace  [4] Acrostic  [5] 7-Segment")
            sub = safe_input("Pilih dekoder [1-5]: ").strip()
            src = str(resolve_smart_input(safe_input("Input teks / @file: ").strip(), as_bytes=False))
            if sub == "1":
                inspect_output(decode_zero_width(src), title="Zero-Width Decoded", op_name="decode_zero_width")
            elif sub == "2":
                inspect_output(decode_unicode_tag_plane(src), title="Tag Plane Decoded", op_name="decode_unicode_tag_plane")
            elif sub == "3":
                inspect_output(decode_trailing_whitespace(src.splitlines()), title="Trailing Whitespace Decoded", op_name="decode_trailing_whitespace")
            elif sub == "4":
                inspect_output(extract_acrostic(src), title="Acrostic Extracted", op_name="extract_acrostic")
            elif sub == "5":
                inspect_output(decode_seven_segment(src), title="7-Segment Decoded", op_name="decode_seven_segment")

        elif choice == "7":
            print("[1] JSON  [2] YAML  [3] INI  [4] CSV")
            sub = safe_input("Pilih format [1-4]: ").strip()
            src = str(resolve_smart_input(safe_input("Input konten / @file: ").strip(), as_bytes=False))
            if sub == "1":
                inspect_output(extract_json_secrets(src), title="JSON Secrets", op_name="extract_json_secrets")
            elif sub == "2":
                inspect_output(extract_yaml_secrets(src), title="YAML Secrets", op_name="extract_yaml_secrets")
            elif sub == "3":
                inspect_output(extract_ini_secrets(src), title="INI Secrets", op_name="extract_ini_secrets")
            elif sub == "4":
                inspect_output(extract_csv_secrets(src), title="CSV Secrets", op_name="extract_csv_secrets")

        elif choice == "8":
            print("[1] Protobuf Raw Wire  [2] MessagePack  [3] CBOR  [4] ASN.1 DER/PEM")
            sub = safe_input("Pilih format biner [1-4]: ").strip()
            raw = resolve_smart_input(safe_input("Input (@file / hex: / b64:): ").strip(), as_bytes=True)
            if sub == "1":
                inspect_output(decode_protobuf_raw(raw), title="Protobuf Raw Fields", op_name="decode_protobuf_raw")
            elif sub == "2":
                inspect_output(decode_msgpack_raw(raw), title="MessagePack Decoded", op_name="decode_msgpack_raw")
            elif sub == "3":
                inspect_output(decode_cbor_raw(raw), title="CBOR Decoded", op_name="decode_cbor_raw")
            elif sub == "4":
                inspect_output(parse_asn1_der_strings(raw), title="ASN.1 DER Strings", op_name="parse_asn1_der_strings")
        else:
            warn("Pilihan tidak valid.")
