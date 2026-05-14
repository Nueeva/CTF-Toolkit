from __future__ import annotations

import binascii
import re

import requests

from ctf_toolkit.ui.common import (
    MAX_RESPONSE_DISPLAY,
    MAX_SUSPICIOUS_DISPLAY,
    SUSPICIOUS_KEYWORDS,
    XOR_SEARCH_KEYWORDS,
    b64_encode_text,
    dummy_login,
    parse_params,
    read_byte_value,
    read_xor_input_data,
    sanitize_params,
    show_text_hex,
    validate_http_url,
    xor_bytes,
    xor_with_repeating_key,
)
from ctf_toolkit.utils.io import read_bytes_file, read_text_or_file, safe_input, warn


def decode_encode_menu() -> None:
    while True:
        print("\n=== Utilities > Encoding ===")
        print("[1] Base64 Encode")
        print("[2] Base64 Decode")
        print("[3] Hex Encode")
        print("[4] Hex Decode")
        print("[5] ROT13")
        print("[6] ROT-n")
        print("[7] XOR (single-byte key)")
        print("[8] XOR alternating key (even/odd)")
        print("[9] XOR repeating key pattern")
        print("[0] Kembali")
        choice = safe_input("Pilih opsi: ").strip()
        if choice == "0":
            return

        try:
            if choice == "1":
                text = safe_input("Masukkan teks: ")
                if not text:
                    warn("Teks kosong.")
                    continue
                print(f"[+] Hasil: {b64_encode_text(text)}")
            elif choice == "2":
                import base64

                text = safe_input("Masukkan teks: ")
                if not text:
                    warn("Teks kosong.")
                    continue
                show_text_hex(base64.b64decode(text))
            elif choice == "3":
                text = safe_input("Masukkan teks: ")
                if not text:
                    warn("Teks kosong.")
                    continue
                print(f"[+] Hasil: {binascii.hexlify(text.encode()).decode()}")
            elif choice == "4":
                text = safe_input("Masukkan teks: ")
                if not text:
                    warn("Teks kosong.")
                    continue
                show_text_hex(binascii.unhexlify(text))
            elif choice in {"5", "6"}:
                from ctf_toolkit.crypto.classical import rot_n

                text = safe_input("Masukkan teks: ")
                if not text:
                    warn("Teks kosong.")
                    continue
                shift = 13 if choice == "5" else int(safe_input("Shift (bisa negatif): ").strip())
                print(f"[+] Hasil: {rot_n(text, shift)}")
            elif choice == "7":
                text = safe_input("Masukkan teks: ")
                if not text:
                    warn("Teks kosong.")
                    continue
                key = int(safe_input("Masukkan key (0-255): ").strip())
                if not 0 <= key <= 255:
                    warn("Key harus 0-255.")
                    continue
                show_text_hex(xor_bytes(text.encode(), key), "XOR")
            elif choice == "8":
                data = read_xor_input_data(safe_input, read_bytes_file)
                if not data:
                    warn("Data kosong.")
                    continue
                even_key = read_byte_value("Even key", safe_input)
                odd_key = read_byte_value("Odd key", safe_input)
                show_text_hex(xor_with_repeating_key(data, bytes([even_key, odd_key])), "XOR alternating")
            elif choice == "9":
                from ctf_toolkit.utils.parse import parse_byte_list

                data = read_xor_input_data(safe_input, read_bytes_file)
                if not data:
                    warn("Data kosong.")
                    continue
                key_pattern = parse_byte_list(
                    safe_input("Masukkan key pattern (contoh 10,8 atau 0x10,0x08): ")
                )
                if not key_pattern:
                    warn("Key pattern kosong.")
                    continue
                show_text_hex(xor_with_repeating_key(data, key_pattern), "XOR repeating")
            else:
                warn("Pilihan tidak valid.")
        except (ValueError, binascii.Error) as exc:
            warn(f"Error: {exc}")


def xor_brute_force_menu() -> None:
    print("\n=== Utilities > XOR Brute Force ===")
    try:
        data = read_xor_input_data(safe_input, read_bytes_file)
    except ValueError as exc:
        warn(f"Error: {exc}")
        return

    if not data:
        warn("Data kosong.")
        return

    print(f"\n[+] Mencari hasil yang mengandung kata: {', '.join(XOR_SEARCH_KEYWORDS)}")
    found = False
    for key in range(256):
        candidate = xor_bytes(data, key).decode("utf-8", errors="ignore")
        low = candidate.lower()
        if any(keyword in low for keyword in XOR_SEARCH_KEYWORDS):
            found = True
            print(f"\n--- Key {key} ---")
            print(candidate)

    if not found:
        print("[-] Tidak ada kandidat yang cocok.")


def regex_flag_finder_menu() -> None:
    print("\n=== Utilities > Regex Flag Finder ===")
    data = read_text_or_file()
    if not data:
        warn("Tidak ada data untuk diproses.")
        return

    max_len = 200
    patterns = [
        rf"flag\{{[^\n\r\}}]{{1,{max_len}}}\}}",
        rf"CTF\{{[^\n\r\}}]{{1,{max_len}}}\}}",
        rf"[A-Za-z0-9_\-]+\{{[^\n\r\}}]{{1,{max_len}}}\}}",
        rf"FLAG\[[^\n\r\]]{{1,{max_len}}}\]",
        rf"LKS\{{[^\n\r\}}]{{1,{max_len}}}\}}",
        rf"LKSJAKTIM\{{[^\n\r\}}]{{1,{max_len}}}\}}",
        rf"LKS[-_\s]?JAKTIM\{{[^\n\r\}}]{{1,{max_len}}}\}}",
    ]

    results = set()
    for pattern in patterns:
        results.update(re.findall(pattern, data, flags=re.IGNORECASE))

    if results:
        print("[+] Flag pattern ditemukan:")
        for idx, value in enumerate(sorted(results), start=1):
            print(f"  {idx}. {value}")
    else:
        print("[-] Tidak ditemukan flag pattern.")


def file_scanner_menu() -> None:
    print("\n=== Utilities > File Scanner / Strings ===")
    path = safe_input("Masukkan path file binary: ").strip()
    raw = read_bytes_file(path)
    if not raw:
        warn("Gagal membaca file atau file kosong.")
        return

    from ctf_toolkit.forensics.pyc_decompile import decompile_pyc_if_applicable
    from ctf_toolkit.utils.pager import page_text
    from ctf_toolkit.utils.text import extract_printable_strings, hexdump, shannon_entropy

    try:
        decompiled = decompile_pyc_if_applicable(path)
    except (ValueError, FileNotFoundError) as exc:
        decompiled = None
        warn(f"PYC decompile gagal: {exc}")
    if decompiled:
        tool, output = decompiled
        print(f"[+] Decompiler: {tool}")
        if output.strip():
            page_text(output)
        else:
            warn("Output decompiler kosong.")

    try:
        min_len = int(safe_input("Min printable string length [default 4]: ").strip() or "4")
    except ValueError:
        min_len = 4

    strings_found = extract_printable_strings(raw, min_len=min_len)
    print(f"[+] Total printable strings: {len(strings_found)}")
    print(f"[+] Shannon entropy: {shannon_entropy(raw):.4f}")

    suspicious = [s for s in strings_found if any(k in s.lower() for k in SUSPICIOUS_KEYWORDS)]
    if suspicious:
        print("[+] String mencurigakan:")
        for idx, value in enumerate(suspicious[:MAX_SUSPICIOUS_DISPLAY], start=1):
            print(f"  {idx}. {value}")

    dump_len = int(safe_input("Preview hexdump berapa byte? [default 128]: ").strip() or "128")
    print("[+] Hexdump preview:")
    print(hexdump(raw[: max(0, dump_len)]))


def http_request_tester_menu() -> None:
    print("\n=== Utilities > HTTP Request Tester ===")
    method = safe_input("Method [GET/POST]: ").strip().upper()
    url = safe_input("Masukkan URL: ").strip()

    if method not in {"GET", "POST"}:
        warn("Method harus GET atau POST.")
        return
    if not url or not validate_http_url(url):
        warn("URL harus diawali http:// atau https://")
        return

    from ctf_toolkit.utils.text import redact_sensitive_text

    param_text = safe_input("Masukkan parameter (format k=v,k2=v2) atau kosong: ")
    params = sanitize_params(parse_params(param_text))
    verify_ssl = safe_input("Verifikasi SSL certificate? [Y/n]: ").strip().lower() != "n"
    if not verify_ssl:
        warn("Warning: SSL verification dimatikan. Gunakan hanya untuk lab/CTF lokal.")

    try:
        if method == "GET":
            response = requests.get(url, params=params, timeout=10, verify=verify_ssl)
        else:
            response = requests.post(url, data=params, timeout=10, verify=verify_ssl)

        print(f"[+] Status: {response.status_code}")
        safe_response = redact_sensitive_text(response.text)
        print("[+] Response:")
        print(safe_response[:MAX_RESPONSE_DISPLAY])
    except requests.RequestException as exc:
        warn(f"HTTP request gagal: {exc}")


def simple_wordlist_brute_menu() -> None:
    print("\n=== Utilities > Simple Wordlist Brute (Simulasi) ===")
    raw = safe_input("Wordlist (pisah koma): ")
    words = [item.strip() for item in raw.split(",") if item.strip()]
    if not words:
        warn("Wordlist kosong.")
        return

    for idx, word in enumerate(words, start=1):
        print(f"[*] Coba #{idx}: {word}")
        if dummy_login(word):
            print(f"[+] Password ditemukan: {word}")
            return
    print("[-] Tidak ada password yang cocok.")


def menu() -> None:
    while True:
        print("\n=== Utilities ===")
        print("[1] Encoding & XOR")
        print("[2] XOR Brute Force")
        print("[3] Regex Flag Finder")
        print("[4] File Scanner / Strings")
        print("[5] HTTP Request Tester")
        print("[6] Simple Wordlist Brute")
        print("[0] Kembali")
        choice = safe_input("Pilih opsi: ").strip()

        if choice == "0":
            return
        if choice == "1":
            decode_encode_menu()
        elif choice == "2":
            xor_brute_force_menu()
        elif choice == "3":
            regex_flag_finder_menu()
        elif choice == "4":
            file_scanner_menu()
        elif choice == "5":
            http_request_tester_menu()
        elif choice == "6":
            simple_wordlist_brute_menu()
        else:
            warn("Pilihan tidak valid.")
