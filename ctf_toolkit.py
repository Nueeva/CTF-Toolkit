#!/usr/bin/env python3
"""CTF Toolkit CLI sederhana untuk analisis challenge cybersecurity."""

import base64
import binascii
import os
import re
import requests
import sys

# Kata kunci umum untuk filtering hasil yang menarik.
SUSPICIOUS_KEYWORDS = ["flag", "ctf", "key", "password", "secret", "token", "admin"]
FLAG_MAX_CONTENT_LEN = 200


def safe_input(prompt):
    """Membaca input user dengan aman agar tidak crash saat EOF/KeyboardInterrupt."""
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        print("\n[!] Input dibatalkan.")
        return ""


def parse_params(param_text):
    """Ubah format key=value,key2=value2 menjadi dictionary."""
    params = {}
    if not param_text.strip():
        return params

    for pair in param_text.split(","):
        pair = pair.strip()
        if not pair:
            continue
        if "=" not in pair:
            print(f"[!] Lewati parameter tidak valid: {pair}")
            continue
        key, value = pair.split("=", 1)
        params[key.strip()] = value.strip()
    return params


def redact_sensitive_text(text):
    """Redact pola kredensial sederhana sebelum ditampilkan ke terminal."""
    redacted = re.sub(r"(?i)(password\s*[=:]\s*)([^\s&]+)", r"\1[REDACTED]", text)
    redacted = re.sub(r"(?i)(token\s*[=:]\s*)([^\s&]+)", r"\1[REDACTED]", redacted)
    redacted = re.sub(r"(?i)(secret\s*[=:]\s*)([^\s&]+)", r"\1[REDACTED]", redacted)
    return redacted


def read_text_or_file():
    """Minta user memilih input dari teks langsung atau file."""
    print("\n[1] Input teks langsung")
    print("[2] Input dari file")
    choice = safe_input("Pilih sumber input: ").strip()

    if choice == "1":
        return safe_input("Masukkan teks: ")

    if choice == "2":
        path = safe_input("Masukkan path file: ").strip()
        if not path:
            print("[!] Path file kosong.")
            return ""
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as file:
                return file.read()
        except OSError as exc:
            print(f"[!] Gagal membaca file: {exc}")
            return ""

    print("[!] Pilihan tidak valid.")
    return ""


def xor_bytes(data_bytes, key):
    """XOR setiap byte dengan satu nilai key (0-255)."""
    return bytes(byte ^ key for byte in data_bytes)


def decode_tools_menu():
    """Submenu untuk encode/decode sederhana."""
    while True:
        print("\n=== Decode Tools ===")
        print("[1] Base64 Encode")
        print("[2] Base64 Decode")
        print("[3] Hex Encode")
        print("[4] Hex Decode")
        print("[5] ROT13")
        print("[6] XOR (dengan key input user)")
        print("[0] Kembali")

        choice = safe_input("Pilih opsi: ").strip()

        if choice == "0":
            return

        text = safe_input("Masukkan teks: ")
        if text == "":
            print("[!] Teks kosong.")
            continue

        try:
            if choice == "1":
                encoded = base64.b64encode(text.encode("utf-8")).decode("utf-8")
                print(f"[+] Hasil Base64 Encode: {encoded}")
            elif choice == "2":
                decoded = base64.b64decode(text).decode("utf-8", errors="ignore")
                print(f"[+] Hasil Base64 Decode: {decoded}")
            elif choice == "3":
                encoded = binascii.hexlify(text.encode("utf-8")).decode("utf-8")
                print(f"[+] Hasil Hex Encode: {encoded}")
            elif choice == "4":
                decoded = binascii.unhexlify(text).decode("utf-8", errors="ignore")
                print(f"[+] Hasil Hex Decode: {decoded}")
            elif choice == "5":
                # ROT13 manual tanpa import tambahan.
                result = []
                for ch in text:
                    if "a" <= ch <= "z":
                        result.append(chr((ord(ch) - ord("a") + 13) % 26 + ord("a")))
                    elif "A" <= ch <= "Z":
                        result.append(chr((ord(ch) - ord("A") + 13) % 26 + ord("A")))
                    else:
                        result.append(ch)
                print(f"[+] Hasil ROT13: {''.join(result)}")
            elif choice == "6":
                key_input = safe_input("Masukkan key (0-255): ").strip()
                key = int(key_input)
                if key < 0 or key > 255:
                    print("[!] Key harus 0-255.")
                    continue
                xored = xor_bytes(text.encode("utf-8"), key)
                print(f"[+] Hasil XOR (hex): {xored.hex()}")
                print(f"[+] Hasil XOR (text): {xored.decode('utf-8', errors='ignore')}")
            else:
                print("[!] Pilihan tidak valid.")
        except (ValueError, binascii.Error) as exc:
            print(f"[!] Error proses data: {exc}")


def xor_brute_force():
    """Brute force XOR single-byte key (0-255) dan tampilkan hasil yang relevan."""
    print("\n=== XOR Brute Force ===")

    mode = safe_input("Input [1] teks / [2] file: ").strip()
    data = b""

    if mode == "1":
        plain = safe_input("Masukkan ciphertext (teks): ")
        data = plain.encode("utf-8", errors="ignore")
    elif mode == "2":
        path = safe_input("Masukkan path file: ").strip()
        try:
            with open(path, "rb") as file:
                data = file.read()
        except OSError as exc:
            print(f"[!] Gagal membaca file: {exc}")
            return
    else:
        print("[!] Pilihan tidak valid.")
        return

    if not data:
        print("[!] Data kosong.")
        return

    print("\n[+] Mencari hasil yang mengandung kata: flag, ctf, key")
    found = False

    for key in range(256):
        candidate = xor_bytes(data, key).decode("utf-8", errors="ignore")
        low = candidate.lower()
        if "flag" in low or "ctf" in low or "key" in low:
            found = True
            print(f"\n--- Key {key} ---")
            print(candidate)

    if not found:
        print("[-] Tidak ada kandidat yang cocok.")


def regex_flag_finder():
    """Cari pola flag umum dari teks atau file."""
    print("\n=== Regex Flag Finder ===")
    data = read_text_or_file()
    if not data:
        print("[!] Tidak ada data untuk diproses.")
        return

    # Batas panjang konten flag dibuat konfigurable untuk menghindari over-match.
    patterns = [
        rf"flag\{{[^\n\r\}}]{{1,{FLAG_MAX_CONTENT_LEN}}}\}}",
        rf"CTF\{{[^\n\r\}}]{{1,{FLAG_MAX_CONTENT_LEN}}}\}}",
        rf"[A-Za-z0-9_\-]+\{{[^\n\r\}}]{{1,{FLAG_MAX_CONTENT_LEN}}}\}}",
        rf"FLAG\[[^\n\r\]]{{1,{FLAG_MAX_CONTENT_LEN}}}\]",
    ]

    results = set()
    for pattern in patterns:
        matches = re.findall(pattern, data)
        results.update(matches)

    if results:
        print("[+] Flag pattern ditemukan:")
        for idx, value in enumerate(sorted(results), start=1):
            print(f"  {idx}. {value}")
    else:
        print("[-] Tidak ditemukan flag pattern.")


def extract_printable_strings(raw_bytes, min_len=4):
    """Ekstrak string printable dari data biner."""
    text = ''.join(chr(b) if 32 <= b <= 126 else '\n' for b in raw_bytes)
    return [line for line in text.splitlines() if len(line) >= min_len]


def file_scanner():
    """Scan file binary, ekstrak string printable, dan filter kata mencurigakan."""
    print("\n=== File Scanner ===")
    path = safe_input("Masukkan path file binary: ").strip()

    if not path:
        print("[!] Path kosong.")
        return
    if not os.path.isfile(path):
        print("[!] File tidak ditemukan.")
        return

    try:
        with open(path, "rb") as file:
            raw = file.read()
    except OSError as exc:
        print(f"[!] Gagal membaca file: {exc}")
        return

    strings_found = extract_printable_strings(raw)
    print(f"[+] Total printable strings: {len(strings_found)}")

    suspicious = []
    for item in strings_found:
        low = item.lower()
        if any(keyword in low for keyword in SUSPICIOUS_KEYWORDS):
            suspicious.append(item)

    if suspicious:
        print("[+] String mencurigakan:")
        for idx, value in enumerate(suspicious[:100], start=1):
            print(f"  {idx}. {value}")
        if len(suspicious) > 100:
            print(f"[i] {len(suspicious) - 100} hasil lain disembunyikan.")
    else:
        print("[-] Tidak ada string mencurigakan terdeteksi.")


def http_request_tester():
    """Tester GET/POST sederhana dengan parameter manual."""
    print("\n=== HTTP Request Tester ===")
    method = safe_input("Method [GET/POST]: ").strip().upper()
    url = safe_input("Masukkan URL: ").strip()

    if method not in {"GET", "POST"}:
        print("[!] Method harus GET atau POST.")
        return
    if not url:
        print("[!] URL tidak boleh kosong.")
        return

    param_text = safe_input("Masukkan parameter (format k=v,k2=v2) atau kosong: ")
    params = parse_params(param_text)

    try:
        if method == "GET":
            response = requests.get(url, params=params, timeout=10, verify=True)
        else:
            response = requests.post(url, data=params, timeout=10, verify=True)

        print(f"[+] Status: {response.status_code}")
        print("[!] Warning: Output response untuk analisis, hindari membagikan data sensitif.")
        safe_response = redact_sensitive_text(response.text)
        print("[+] Response:")
        print(safe_response[:4000])
        if len(safe_response) > 4000:
            print("[i] Response dipotong hingga 4000 karakter.")
    except requests.RequestException as exc:
        print(f"[!] HTTP request gagal: {exc}")


def dummy_login(password):
    """Fungsi dummy untuk simulasi brute force wordlist."""
    # Bisa dioverride via environment variable untuk memudahkan modifikasi.
    correct_password = os.getenv("DUMMY_LOGIN_PASSWORD", "ctf123")
    return password == correct_password


def simple_wordlist_brute():
    """Brute force dasar dari input wordlist manual ke fungsi dummy."""
    print("\n=== Simple Wordlist Brute (Simulasi) ===")
    print("Masukkan kandidat password dipisah koma, contoh: admin,123456,ctf123")
    raw = safe_input("Wordlist: ")

    words = [item.strip() for item in raw.split(",") if item.strip()]
    if not words:
        print("[!] Wordlist kosong.")
        return

    for idx, word in enumerate(words, start=1):
        print(f"[*] Coba #{idx}: {word}")
        if dummy_login(word):
            print(f"[+] Password ditemukan: {word}")
            return

    print("[-] Tidak ada password yang cocok.")


def show_main_menu():
    """Tampilkan menu utama toolkit."""
    print("\n=== CTF Toolkit CLI ===")
    print("[1] Decode Tools")
    print("[2] XOR Brute Force")
    print("[3] Regex Flag Finder")
    print("[4] File Scanner")
    print("[5] HTTP Request Tester")
    print("[6] Simple Wordlist Brute")
    print("[0] Keluar")


def main():
    """Entry point program dengan loop menu."""
    while True:
        show_main_menu()
        choice = safe_input("Pilih opsi menu: ").strip()

        if choice == "1":
            decode_tools_menu()
        elif choice == "2":
            xor_brute_force()
        elif choice == "3":
            regex_flag_finder()
        elif choice == "4":
            file_scanner()
        elif choice == "5":
            http_request_tester()
        elif choice == "6":
            simple_wordlist_brute()
        elif choice == "0":
            print("[+] Keluar dari toolkit. Bye!")
            break
        else:
            print("[!] Pilihan tidak valid, coba lagi.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[+] Dihentikan user. Bye!")
        sys.exit(0)
