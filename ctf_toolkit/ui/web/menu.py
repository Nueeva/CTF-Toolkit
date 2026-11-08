from __future__ import annotations

import json

from ctf_toolkit.ui.common import print_table, read_bytes_prompt, show_text_hex
from ctf_toolkit.utils.io import error, safe_input, warn
from ctf_toolkit.utils.menu import run_menu


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
    run_menu(
        "Web > Attacks & Logic",
        {
            "1": ("IDOR Payload Matrix", idor_payload_menu),
            "2": ("Mass Assignment Static Heuristic", mass_assignment_menu),
        },
    )


def menu() -> None:
    from ctf_toolkit.web.helpers import (
        REQUEST_TEMPLATES,
        b64url_decode,
        b64url_encode,
        build_command_injection_payload,
        build_lfi_traversal_path,
        build_sqli_auth_bypass,
        build_ssrf_metadata_url,
        jwt_decode_no_verify,
        url_decode,
        url_encode,
    )

    def url_encode_action() -> None:
        try:
            print(url_encode(safe_input("Text: ")))
        except ValueError as exc:
            warn(f"Error: {exc}")

    def url_decode_action() -> None:
        try:
            print(url_decode(safe_input("Text: ")))
        except ValueError as exc:
            warn(f"Error: {exc}")

    def b64url_encode_action() -> None:
        try:
            data = read_bytes_prompt("Data", safe_input)
            out = b64url_encode(data)
            print(out)
            print(f"hex input: {data.hex()}")
        except ValueError as exc:
            warn(f"Error: {exc}")

    def b64url_decode_action() -> None:
        try:
            show_text_hex(b64url_decode(safe_input("b64url: ")), "Decoded")
        except ValueError as exc:
            warn(f"Error: {exc}")

    def jwt_decode_action() -> None:
        try:
            token = safe_input("JWT: ")
            print(json.dumps(jwt_decode_no_verify(token), indent=2))
            warn("JWT ini TIDAK diverifikasi signature.")
        except ValueError as exc:
            warn(f"Error: {exc}")

    def request_templates_action() -> None:
        warn("Template hanya untuk lab/CTF. Toolkit tidak melakukan auto-scan.")
        for name, payloads in REQUEST_TEMPLATES.items():
            print(f"\n[{name.upper()}]")
            for payload in payloads:
                print(f"- {payload}")

    def attacks_action() -> None:
        attacks_menu()

    def lfi_action() -> None:
        from ctf_toolkit.web.traversal import generate_traversal_payloads
        target = safe_input("Target file [default flag.txt]: ").strip() or "flag.txt"
        depth_raw = safe_input("Max depth [default 5]: ").strip()
        depth = int(depth_raw) if depth_raw.isdigit() else 5
        payloads = generate_traversal_payloads(target, depth)
        print(f"\n=== LFI / Path Traversal Payloads ({len(payloads)}) ===")
        for p in payloads:
            print(p)

    def sqli_action() -> None:
        user = safe_input("Target username [default admin]: ").strip() or "admin"
        print("\n=== SQLi Auth Bypass Payloads ===")
        for tech in ["or_true", "or_1_equals_1", "or_true_hash", "admin_closed", "union_admin"]:
            payload = build_sqli_auth_bypass(username=user, technique=tech)
            print(f"  [{tech:<15}] : {payload}")

    def cmdi_action() -> None:
        base = safe_input("Base IP/Host [default 127.0.0.1]: ").strip() or "127.0.0.1"
        cmd = safe_input("Command to execute [default cat /flag.txt]: ").strip() or "cat /flag.txt"
        print("\n=== Command Injection Delimiter Payloads ===")
        for sep in [";", "|", "&&", "||", "subshell", "newline"]:
            payload = build_command_injection_payload(base_arg=base, separator=sep, command=cmd)
            print(f"  [{sep:<10}] : {repr(payload)}")

    def ssrf_action() -> None:
        print("\n=== Cloud SSRF Metadata Probe Endpoints ===")
        for provider in ["aws", "gcp", "digitalocean", "docker_internal", "localhost"]:
            url = build_ssrf_metadata_url(provider)
            print(f"  [{provider:<15}] : {url}")

    run_menu(
        "Web",
        {
            "1": ("URL Encode", url_encode_action),
            "2": ("URL Decode", url_decode_action),
            "3": ("Base64URL Encode", b64url_encode_action),
            "4": ("Base64URL Decode", b64url_decode_action),
            "5": ("JWT Decode (no verify)", jwt_decode_action),
            "6": ("Request Templates Generator", request_templates_action),
            "7": ("Attacks / Logic Helpers", attacks_action),
            "8": ("LFI / Path Traversal Crafter", lfi_action),
            "9": ("SQLi Auth Bypass Crafter", sqli_action),
            "10": ("Command Injection Crafter", cmdi_action),
            "11": ("Cloud SSRF Prober Endpoints", ssrf_action),
        },
    )
