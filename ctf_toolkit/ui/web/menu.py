from __future__ import annotations

import json

from ctf_toolkit.ui.common import print_table, read_bytes_prompt, show_text_hex
from ctf_toolkit.utils.io import error, safe_input, warn


def idor_payload_menu() -> None:
    from ctf_toolkit.web.idor import (
        build_idor_payloads,
        default_padding_widths,
        iter_id_values,
        parse_id_range,
        parse_padding_widths,
        range_count,
    )

    print("\n=== Web > IDOR Payload Crafter ===")
    raw = safe_input("Target ID atau range (contoh 1 atau 1-10): ").strip()
    if not raw:
        warn("ID kosong.")
        return

    try:
        start, end = parse_id_range(raw)
        total = range_count(start, end)
        if total > 200:
            confirm = safe_input(f"Range berisi {total} ID, lanjut? [y/N]: ").strip().lower()
            if confirm != "y":
                return
        param = safe_input("Nama parameter JSON [default id]: ").strip() or "id"
        widths_raw = safe_input("Padding widths (pisah koma, kosong=auto): ")
        widths = parse_padding_widths(widths_raw, default_padding_widths(max(start, end)))
        for value in iter_id_values(start, end):
            print(f"\n=== ID {value} ===")
            payloads = build_idor_payloads(value, widths)
            if not payloads:
                warn("Tidak ada padding yang valid.")
                continue
            for payload in payloads:
                rows = [
                    ["raw", payload["raw"]],
                    ["raw_base64", payload["raw_base64"]],
                    ["raw_md5", payload["raw_md5"]],
                    ["raw_hex", payload["raw_hex"]],
                    ["padded", payload["padded"]],
                    ["padded_base64", payload["padded_base64"]],
                    ["padded_md5", payload["padded_md5"]],
                    ["padded_hex", payload["padded_hex"]],
                ]
                print_table(["variant", "value"], rows)
                print("json:")
                print(f"  raw   : {json.dumps({param: payload['raw']})}")
                print(f"  b64   : {json.dumps({param: payload['padded_base64']})}")
                print(f"  md5   : {json.dumps({param: payload['raw_md5']})}")
                print(f"  hex   : {json.dumps({param: payload['raw_hex']})}")
                print(f"  padded: {json.dumps({param: payload['padded']})}")
    except ValueError as exc:
        warn(f"Error: {exc}")


def mass_assignment_menu() -> None:
    from ctf_toolkit.web.logic import scan_mass_assignment_files

    print("\n=== Web > Mass Assignment Static Heuristic ===")
    root = safe_input("Root path [default .]: ").strip() or "."
    names_raw = safe_input("Target files (default app.py,models.py): ").strip()
    names = [name.strip() for name in names_raw.split(",") if name.strip()] or ["app.py", "models.py"]
    try:
        results = scan_mass_assignment_files(root, names)
    except ValueError as exc:
        warn(f"Error: {exc}")
        return
    if not results:
        error("Tidak ada pola mass assignment yang terdeteksi.")
        return

    rows: list[list[str]] = []
    for item in results:
        snippet = str(item["snippet"])
        if len(snippet) > 90:
            snippet = snippet[:87] + "..."
        rows.append([str(item["file"]), str(item["line"]), str(item["reason"]), snippet])
    print_table(["file", "line", "reason", "snippet"], rows)


def attacks_menu() -> None:
    while True:
        print("\n=== Web > Attacks & Logic ===")
        print("[1] IDOR Payload Matrix")
        print("[2] Mass Assignment Static Heuristic")
        print("[0] Kembali")
        choice = safe_input("Pilih opsi: ").strip()
        if choice == "0":
            return
        if choice == "1":
            idor_payload_menu()
        elif choice == "2":
            mass_assignment_menu()
        else:
            warn("Pilihan tidak valid.")


def menu() -> None:
    while True:
        print("\n=== Web ===")
        print("[1] URL Encode")
        print("[2] URL Decode")
        print("[3] Base64URL Encode")
        print("[4] Base64URL Decode")
        print("[5] JWT Decode (no verify)")
        print("[6] Request Templates Generator")
        print("[7] Attacks / Logic Helpers")
        print("[0] Kembali")
        choice = safe_input("Pilih opsi: ").strip()
        if choice == "0":
            return

        from ctf_toolkit.web.helpers import (
            REQUEST_TEMPLATES,
            b64url_decode,
            b64url_encode,
            jwt_decode_no_verify,
            url_decode,
            url_encode,
        )

        try:
            if choice == "1":
                print(url_encode(safe_input("Text: ")))
            elif choice == "2":
                print(url_decode(safe_input("Text: ")))
            elif choice == "3":
                data = read_bytes_prompt("Data", safe_input)
                out = b64url_encode(data)
                print(out)
                print(f"hex input: {data.hex()}")
            elif choice == "4":
                show_text_hex(b64url_decode(safe_input("b64url: ")), "Decoded")
            elif choice == "5":
                token = safe_input("JWT: ")
                print(json.dumps(jwt_decode_no_verify(token), indent=2))
                warn("JWT ini TIDAK diverifikasi signature.")
            elif choice == "6":
                warn("Template hanya untuk lab/CTF. Toolkit tidak melakukan auto-scan.")
                for name, payloads in REQUEST_TEMPLATES.items():
                    print(f"\n[{name.upper()}]")
                    for payload in payloads:
                        print(f"- {payload}")
            elif choice == "7":
                attacks_menu()
            else:
                warn("Pilihan tidak valid.")
        except ValueError as exc:
            warn(f"Error: {exc}")
