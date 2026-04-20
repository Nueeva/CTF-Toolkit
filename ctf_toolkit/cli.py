from __future__ import annotations

import base64
import binascii
import hmac
import json
import os
import re
import sys
from pathlib import Path

import requests

from ctf_toolkit.binex.cyclic import cyclic_create, cyclic_find
from ctf_toolkit.binex.elf import parse_elf
from ctf_toolkit.binex.gadgets import scan_gadgets
from ctf_toolkit.binex.pack import p32, p64, u32, u64
from ctf_toolkit.crypto.aes import (
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    aes_ctr_crypt,
    aes_ecb_decrypt,
    aes_ecb_encrypt,
    detect_ecb,
    pkcs7_pad,
    pkcs7_unpad,
)
from ctf_toolkit.crypto.classical import (
    affine_decrypt,
    affine_encrypt,
    apply_substitution,
    atbash,
    caesar_bruteforce,
    caesar_decrypt,
    caesar_encrypt,
    rot_n,
    vigenere_decrypt,
    vigenere_encrypt,
    frequency_analysis,
)
from ctf_toolkit.crypto.hashes import LENGTH_EXTENSION_NOTE, digest
from ctf_toolkit.crypto.prng import lcg_generate, recover_lcg_params_known_mod
from ctf_toolkit.crypto.rsa import (
    common_modulus_attack,
    fermat_factor,
    hastad_broadcast,
    private_exponent_from_factors,
    rsa_decrypt,
    rsa_encrypt,
)
from ctf_toolkit.forensics.filetype import detect_file_magic
from ctf_toolkit.forensics.caesar_helper import suggest_caesar_candidates
from ctf_toolkit.forensics.jpeg_tools import extract_jpeg_fragments, get_jpeg_dimensions, patch_jpeg_dimensions
from ctf_toolkit.forensics.pcap_extract import extract_pcap_artifacts
from ctf_toolkit.forensics.pcap_notes import PCAP_HELP_TEXT
from ctf_toolkit.forensics.zip_recover import list_zip_members, recover_corrupted_zip
from ctf_toolkit.utils.io import read_bytes_file, read_text_or_file, safe_input
from ctf_toolkit.utils.parse import parse_byte_list, parse_bytes, parse_int
from ctf_toolkit.utils.text import extract_printable_strings, hexdump, redact_sensitive_text, shannon_entropy

SUSPICIOUS_KEYWORDS = ["flag", "ctf", "key", "lks", "lksjaktim", "password", "secret", "token", "admin"]
XOR_SEARCH_KEYWORDS = ["flag", "ctf", "key", "lks", "lksjaktim"]
MAX_SUSPICIOUS_DISPLAY = 100
MAX_RESPONSE_DISPLAY = 4000


def parse_params(param_text: str) -> dict[str, str]:
    params: dict[str, str] = {}
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


def sanitize_params(params: dict[str, str]) -> dict[str, str]:
    clean: dict[str, str] = {}
    for key, value in params.items():
        if not re.match(r"^[A-Za-z0-9_.\-\[\]]{1,100}$", key):
            print(f"[!] Lewati key parameter tidak valid: {key}")
            continue
        safe_value = re.sub(r"[\x00-\x1F\x7F]", "", str(value))[:500]
        clean[key] = safe_value
    return clean


def validate_http_url(url: str) -> bool:
    return re.match(r"^https?://", url, flags=re.IGNORECASE) is not None


def xor_bytes(data_bytes: bytes, key: int) -> bytes:
    return bytes(byte ^ key for byte in data_bytes)


def xor_with_repeating_key(data_bytes: bytes, key_bytes: bytes) -> bytes:
    if not key_bytes:
        raise ValueError("key pattern tidak boleh kosong")
    return bytes(data_bytes[idx] ^ key_bytes[idx % len(key_bytes)] for idx in range(len(data_bytes)))


def _looks_like_byte_list(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    lowered = stripped.lower()
    if "0x" in lowered:
        return True
    return "," in stripped and bool(re.search(r"\d", stripped))


def _read_xor_input_data() -> bytes:
    mode = safe_input("Input [1] teks / [2] file: ").strip()
    if mode == "1":
        raw = safe_input("Masukkan data/ciphertext: ")
        if _looks_like_byte_list(raw):
            return parse_byte_list(raw)
        return raw.encode("utf-8", errors="ignore")
    if mode == "2":
        path = safe_input("Masukkan path file: ").strip()
        return read_bytes_file(path)
    raise ValueError("pilihan input tidak valid")


def _read_byte_value(label: str) -> int:
    value = parse_int(safe_input(f"{label} (0-255, dec/0x): ").strip())
    if not 0 <= value <= 255:
        raise ValueError(f"{label} harus 0..255")
    return value


def int_to_bytes(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    size = (value.bit_length() + 7) // 8
    return value.to_bytes(size, "big")


def show_text_hex(data: bytes, title: str = "Hasil") -> None:
    print(f"[+] {title} (hex): {data.hex()}")
    print(f"[+] {title} (text): {data.decode('utf-8', errors='ignore')}")


def decode_encode_menu() -> None:
    while True:
        print("\n=== Decode/Encode ===")
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
                    print("[!] Teks kosong.")
                    continue
                print(f"[+] Hasil: {base64.b64encode(text.encode()).decode()}")
            elif choice == "2":
                text = safe_input("Masukkan teks: ")
                if not text:
                    print("[!] Teks kosong.")
                    continue
                decoded = base64.b64decode(text)
                show_text_hex(decoded)
            elif choice == "3":
                text = safe_input("Masukkan teks: ")
                if not text:
                    print("[!] Teks kosong.")
                    continue
                print(f"[+] Hasil: {binascii.hexlify(text.encode()).decode()}")
            elif choice == "4":
                text = safe_input("Masukkan teks: ")
                if not text:
                    print("[!] Teks kosong.")
                    continue
                decoded = binascii.unhexlify(text)
                show_text_hex(decoded)
            elif choice == "5":
                text = safe_input("Masukkan teks: ")
                if not text:
                    print("[!] Teks kosong.")
                    continue
                print(f"[+] Hasil: {rot_n(text, 13)}")
            elif choice == "6":
                text = safe_input("Masukkan teks: ")
                if not text:
                    print("[!] Teks kosong.")
                    continue
                shift = int(safe_input("Shift (bisa negatif): ").strip())
                print(f"[+] Hasil: {rot_n(text, shift)}")
            elif choice == "7":
                text = safe_input("Masukkan teks: ")
                if not text:
                    print("[!] Teks kosong.")
                    continue
                key = int(safe_input("Masukkan key (0-255): ").strip())
                if not 0 <= key <= 255:
                    print("[!] Key harus 0-255.")
                    continue
                result = xor_bytes(text.encode(), key)
                show_text_hex(result, "XOR")
            elif choice == "8":
                data = _read_xor_input_data()
                if not data:
                    print("[!] Data kosong.")
                    continue
                even_key = _read_byte_value("Even key")
                odd_key = _read_byte_value("Odd key")
                result = xor_with_repeating_key(data, bytes([even_key, odd_key]))
                show_text_hex(result, "XOR alternating")
            elif choice == "9":
                data = _read_xor_input_data()
                if not data:
                    print("[!] Data kosong.")
                    continue
                key_pattern = parse_byte_list(
                    safe_input("Masukkan key pattern (contoh 10,8 atau 0x10,0x08): ")
                )
                if not key_pattern:
                    print("[!] Key pattern kosong.")
                    continue
                result = xor_with_repeating_key(data, key_pattern)
                show_text_hex(result, "XOR repeating")
            else:
                print("[!] Pilihan tidak valid.")
        except (ValueError, binascii.Error) as exc:
            print(f"[!] Error: {exc}")


def xor_brute_force_menu() -> None:
    print("\n=== XOR Brute Force ===")
    try:
        data = _read_xor_input_data()
    except ValueError as exc:
        print(f"[!] Error: {exc}")
        return

    if not data:
        print("[!] Data kosong.")
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
    print("\n=== Regex Flag Finder ===")
    data = read_text_or_file()
    if not data:
        print("[!] Tidak ada data untuk diproses.")
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
    print("\n=== File Scanner / Strings ===")
    path = safe_input("Masukkan path file binary: ").strip()
    raw = read_bytes_file(path)
    if not raw:
        print("[!] Gagal membaca file atau file kosong.")
        return

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
    print("\n=== HTTP Request Tester ===")
    method = safe_input("Method [GET/POST]: ").strip().upper()
    url = safe_input("Masukkan URL: ").strip()

    if method not in {"GET", "POST"}:
        print("[!] Method harus GET atau POST.")
        return
    if not url or not validate_http_url(url):
        print("[!] URL harus diawali http:// atau https://")
        return

    param_text = safe_input("Masukkan parameter (format k=v,k2=v2) atau kosong: ")
    params = sanitize_params(parse_params(param_text))
    verify_ssl = safe_input("Verifikasi SSL certificate? [Y/n]: ").strip().lower() != "n"
    if not verify_ssl:
        print("[!] Warning: SSL verification dimatikan. Gunakan hanya untuk lab/CTF lokal.")

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
        print(f"[!] HTTP request gagal: {exc}")


def dummy_login(password: str) -> bool:
    """Simulation-only credential check for CTF labs; never use for real authentication."""
    correct_password = os.getenv("DUMMY_LOGIN_PASSWORD", "ctf123")
    return hmac.compare_digest(password, correct_password)


def simple_wordlist_brute_menu() -> None:
    print("\n=== Simple Wordlist Brute (Simulasi) ===")
    raw = safe_input("Wordlist (pisah koma): ")
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


def crypto_classical_menu() -> None:
    while True:
        print("\n=== Crypto > Classical ===")
        print("[1] Caesar Encrypt")
        print("[2] Caesar Decrypt")
        print("[3] Caesar Bruteforce")
        print("[4] Atbash")
        print("[5] Vigenere Encrypt")
        print("[6] Vigenere Decrypt")
        print("[7] Affine Encrypt")
        print("[8] Affine Decrypt")
        print("[9] Substitution Apply + Frequency")
        print("[0] Kembali")
        choice = safe_input("Pilih opsi: ").strip()
        if choice == "0":
            return
        text = safe_input("Masukkan teks: ")

        try:
            if choice == "1":
                shift = int(safe_input("Shift: "))
                print(caesar_encrypt(text, shift))
            elif choice == "2":
                shift = int(safe_input("Shift: "))
                print(caesar_decrypt(text, shift))
            elif choice == "3":
                for shift, value in caesar_bruteforce(text):
                    print(f"{shift:2d}: {value}")
            elif choice == "4":
                print(atbash(text))
            elif choice == "5":
                key = safe_input("Key: ")
                print(vigenere_encrypt(text, key))
            elif choice == "6":
                key = safe_input("Key: ")
                print(vigenere_decrypt(text, key))
            elif choice == "7":
                a = int(safe_input("a: "))
                b = int(safe_input("b: "))
                print(affine_encrypt(text, a, b))
            elif choice == "8":
                a = int(safe_input("a: "))
                b = int(safe_input("b: "))
                print(affine_decrypt(text, a, b))
            elif choice == "9":
                mapping_text = safe_input("Mapping (contoh A=Q,B=W,...): ")
                mapping = {}
                for pair in mapping_text.split(","):
                    if "=" not in pair:
                        continue
                    k, v = pair.split("=", 1)
                    if k.strip() and v.strip() and k.strip()[0].isalpha() and v.strip()[0].isalpha():
                        mapping[k.strip()[0].upper()] = v.strip()[0].upper()
                print("[+] Hasil substitution:")
                print(apply_substitution(text, mapping))
                print("[+] Frequency analysis:")
                for ch, count in frequency_analysis(text):
                    print(f"  {ch}: {count}")
            else:
                print("[!] Pilihan tidak valid.")
        except ValueError as exc:
            print(f"[!] Error: {exc}")


def crypto_rsa_menu() -> None:
    while True:
        print("\n=== Crypto > RSA ===")
        print("[1] Encrypt (m^e mod n)")
        print("[2] Decrypt (c^d mod n)")
        print("[3] Common Modulus Attack")
        print("[4] Hastad Broadcast Attack")
        print("[5] Fermat Factorization")
        print("[6] Hitung d dari faktor prima")
        print("[0] Kembali")
        choice = safe_input("Pilih opsi: ").strip()
        if choice == "0":
            return

        try:
            if choice == "1":
                m = parse_int(safe_input("m (dec/0x): "))
                n = parse_int(safe_input("n (dec/0x): "))
                e = parse_int(safe_input("e (dec/0x): "))
                c = rsa_encrypt(m, n, e)
                print(f"[+] c: {c}")
                print(f"[+] c (hex): 0x{c:x}")
            elif choice == "2":
                c = parse_int(safe_input("c (dec/0x): "))
                n = parse_int(safe_input("n (dec/0x): "))
                d = parse_int(safe_input("d (dec/0x): "))
                m = rsa_decrypt(c, n, d)
                m_bytes = int_to_bytes(m)
                print(f"[+] m: {m}")
                print(f"[+] m (hex): 0x{m:x}")
                show_text_hex(m_bytes, "m bytes")
            elif choice == "3":
                c1 = parse_int(safe_input("c1: "))
                e1 = parse_int(safe_input("e1: "))
                c2 = parse_int(safe_input("c2: "))
                e2 = parse_int(safe_input("e2: "))
                n = parse_int(safe_input("n: "))
                m = common_modulus_attack(c1, e1, c2, e2, n)
                m_bytes = int_to_bytes(m)
                print(f"[+] recovered m: {m}")
                print(f"[+] recovered m (hex): 0x{m:x}")
                show_text_hex(m_bytes, "m bytes")
            elif choice == "4":
                e = parse_int(safe_input("e kecil (mis. 3): "))
                k = int(safe_input("Jumlah pasangan (c,n): ").strip())
                c_list: list[int] = []
                n_list: list[int] = []
                for i in range(k):
                    c_list.append(parse_int(safe_input(f"c[{i}]: ")))
                    n_list.append(parse_int(safe_input(f"n[{i}]: ")))
                m = hastad_broadcast(c_list, n_list, e)
                m_bytes = int_to_bytes(m)
                print(f"[+] recovered m: {m}")
                print(f"[+] recovered m (hex): 0x{m:x}")
                show_text_hex(m_bytes, "m bytes")
            elif choice == "5":
                n = parse_int(safe_input("n: "))
                max_iter = int(safe_input("max_iter [default 1000000]: ").strip() or "1000000")
                factors = fermat_factor(n, max_iter=max_iter)
                if not factors:
                    print("[-] Faktor tidak ditemukan (mungkin prime tidak dekat).")
                else:
                    p, q = factors
                    print(f"[+] p: {p}")
                    print(f"[+] q: {q}")
                    print(f"[+] p hex: 0x{p:x}")
                    print(f"[+] q hex: 0x{q:x}")
            elif choice == "6":
                e = parse_int(safe_input("e: "))
                factors_text = safe_input("Daftar faktor prima pisah koma (dec/0x): ")
                factors = [parse_int(x.strip()) for x in factors_text.split(",") if x.strip()]
                d = private_exponent_from_factors(e, factors)
                print(f"[+] d: {d}")
                print(f"[+] d (hex): 0x{d:x}")
            else:
                print("[!] Pilihan tidak valid.")
        except ValueError as exc:
            print(f"[!] Error: {exc}")


def _read_bytes_prompt(label: str) -> bytes:
    raw = safe_input(f"{label} (prefix hex:/b64:/raw:, default auto): ")
    return parse_bytes(raw, mode="auto")


def crypto_aes_menu() -> None:
    while True:
        print("\n=== Crypto > AES ===")
        print("[1] ECB Encrypt")
        print("[2] ECB Decrypt")
        print("[3] CBC Encrypt")
        print("[4] CBC Decrypt")
        print("[5] CTR Encrypt/Decrypt")
        print("[6] PKCS#7 Pad")
        print("[7] PKCS#7 Unpad")
        print("[8] ECB Detect")
        print("[0] Kembali")
        choice = safe_input("Pilih opsi: ").strip()
        if choice == "0":
            return

        try:
            if choice == "1":
                pt = _read_bytes_prompt("Plaintext")
                key = _read_bytes_prompt("Key")
                use_padding = safe_input("Gunakan PKCS#7 padding? [Y/n]: ").strip().lower() != "n"
                ct = aes_ecb_encrypt(pt, key, use_padding=use_padding)
                show_text_hex(ct, "Ciphertext")
            elif choice == "2":
                ct = _read_bytes_prompt("Ciphertext")
                key = _read_bytes_prompt("Key")
                do_unpad = safe_input("Lepas PKCS#7 padding? [Y/n]: ").strip().lower() != "n"
                pt = aes_ecb_decrypt(ct, key, unpad=do_unpad)
                show_text_hex(pt, "Plaintext")
            elif choice == "3":
                pt = _read_bytes_prompt("Plaintext")
                key = _read_bytes_prompt("Key")
                iv = _read_bytes_prompt("IV (16 byte)")
                use_padding = safe_input("Gunakan PKCS#7 padding? [Y/n]: ").strip().lower() != "n"
                ct = aes_cbc_encrypt(pt, key, iv, use_padding=use_padding)
                show_text_hex(ct, "Ciphertext")
            elif choice == "4":
                ct = _read_bytes_prompt("Ciphertext")
                key = _read_bytes_prompt("Key")
                iv = _read_bytes_prompt("IV (16 byte)")
                do_unpad = safe_input("Lepas PKCS#7 padding? [Y/n]: ").strip().lower() != "n"
                pt = aes_cbc_decrypt(ct, key, iv, unpad=do_unpad)
                show_text_hex(pt, "Plaintext")
            elif choice == "5":
                data = _read_bytes_prompt("Data")
                key = _read_bytes_prompt("Key")
                nonce = _read_bytes_prompt("Nonce (disarankan <=15 byte)")
                out = aes_ctr_crypt(data, key, nonce)
                show_text_hex(out, "Output")
            elif choice == "6":
                data = _read_bytes_prompt("Data")
                padded = pkcs7_pad(data)
                show_text_hex(padded, "Padded")
            elif choice == "7":
                data = _read_bytes_prompt("Data")
                unpadded = pkcs7_unpad(data)
                show_text_hex(unpadded, "Unpadded")
            elif choice == "8":
                data = _read_bytes_prompt("Ciphertext")
                repeats, blocks = detect_ecb(data)
                print(f"[+] Block total: {blocks}")
                print(f"[+] Block berulang: {repeats}")
                print("[+] Indikasi ECB kuat." if repeats > 0 else "[-] Tidak ada pengulangan blok mencolok.")
            else:
                print("[!] Pilihan tidak valid.")
        except (ValueError, binascii.Error) as exc:
            print(f"[!] Error: {exc}")


def crypto_prng_menu() -> None:
    while True:
        print("\n=== Crypto > PRNG ===")
        print("[1] LCG Generate")
        print("[2] LCG Recover (m known)")
        print("[0] Kembali")
        choice = safe_input("Pilih opsi: ").strip()
        if choice == "0":
            return

        try:
            if choice == "1":
                seed = parse_int(safe_input("seed: "))
                a = parse_int(safe_input("a: "))
                c = parse_int(safe_input("c: "))
                m = parse_int(safe_input("m: "))
                count = int(safe_input("count: "))
                values = lcg_generate(seed, a, c, m, count)
                for idx, value in enumerate(values):
                    print(f"{idx}: {value} (0x{value:x})")
            elif choice == "2":
                m = parse_int(safe_input("m: "))
                outputs = [parse_int(x.strip()) for x in safe_input("outputs pisah koma: ").split(",") if x.strip()]
                a, c = recover_lcg_params_known_mod(outputs, m)
                print(f"[+] a: {a} (0x{a:x})")
                print(f"[+] c: {c} (0x{c:x})")
            else:
                print("[!] Pilihan tidak valid.")
        except ValueError as exc:
            print(f"[!] Error: {exc}")


def crypto_hash_menu() -> None:
    print("\n=== Crypto > Hashes ===")
    data = _read_bytes_prompt("Data")
    for algo in ("md5", "sha1", "sha256"):
        print(f"{algo}: {digest(data, algo)}")
    print(f"[i] {LENGTH_EXTENSION_NOTE}")


def crypto_menu() -> None:
    while True:
        print("\n=== Crypto Tools ===")
        print("[1] Classical Ciphers")
        print("[2] RSA")
        print("[3] AES")
        print("[4] PRNG")
        print("[5] Hashes")
        print("[0] Kembali")
        choice = safe_input("Pilih opsi: ").strip()
        if choice == "0":
            return
        if choice == "1":
            crypto_classical_menu()
        elif choice == "2":
            crypto_rsa_menu()
        elif choice == "3":
            crypto_aes_menu()
        elif choice == "4":
            crypto_prng_menu()
        elif choice == "5":
            crypto_hash_menu()
        else:
            print("[!] Pilihan tidak valid.")


def binex_menu() -> None:
    while True:
        print("\n=== BinEx Tools ===")
        print("[1] Cyclic Pattern Create")
        print("[2] Cyclic Offset Find")
        print("[3] Pack/Unpack (p32/p64/u32/u64)")
        print("[4] ELF Triage / Checksec-lite")
        print("[5] Gadget Scan (ret, pop rdi; ret)")
        print("[0] Kembali")
        choice = safe_input("Pilih opsi: ").strip()
        if choice == "0":
            return

        try:
            if choice == "1":
                length = int(safe_input("Length: "))
                pattern = cyclic_create(length)
                show_text_hex(pattern, "Pattern")
            elif choice == "2":
                needle_raw = safe_input("Needle (text/hex:...): ").strip()
                needle = parse_bytes(needle_raw, mode="auto")
                max_len = int(safe_input("max_len [default 100000]: ").strip() or "100000")
                offset = cyclic_find(needle, max_len=max_len)
                print(f"[+] Offset: {offset}")
            elif choice == "3":
                v = parse_int(safe_input("Nilai integer (dec/0x): "))
                p32v = p32(v)
                p64v = p64(v)
                print(f"p32 hex: {p32v.hex()} | u32: {u32(p32v)}")
                print(f"p64 hex: {p64v.hex()} | u64: {u64(p64v)}")
            elif choice == "4":
                path = safe_input("Path ELF: ")
                info = parse_elf(path)
                print(json.dumps(info, indent=2))
            elif choice == "5":
                path = safe_input("Path binary: ")
                limit = int(safe_input("limit [default 200]: ").strip() or "200")
                data = scan_gadgets(path, limit=limit)
                print(f"ret count: {len(data['ret'])}")
                print(f"ret sample: {[hex(x) for x in data['ret'][:20]]}")
                print(f"pop rdi; ret count: {len(data['pop_rdi_ret'])}")
                print(f"pop rdi; ret sample: {[hex(x) for x in data['pop_rdi_ret'][:20]]}")
            else:
                print("[!] Pilihan tidak valid.")
        except (ValueError, OSError, binascii.Error) as exc:
            print(f"[!] Error: {exc}")


def web_helpers_menu() -> None:
    from ctf_toolkit.web.helpers import (
        REQUEST_TEMPLATES,
        b64url_decode,
        b64url_encode,
        jwt_decode_no_verify,
        url_decode,
        url_encode,
    )

    while True:
        print("\n=== Web Helpers (Safe) ===")
        print("[1] URL Encode")
        print("[2] URL Decode")
        print("[3] Base64URL Encode")
        print("[4] Base64URL Decode")
        print("[5] JWT Decode (no verify)")
        print("[6] Request Templates Generator")
        print("[0] Kembali")
        choice = safe_input("Pilih opsi: ").strip()
        if choice == "0":
            return

        try:
            if choice == "1":
                print(url_encode(safe_input("Text: ")))
            elif choice == "2":
                print(url_decode(safe_input("Text: ")))
            elif choice == "3":
                data = _read_bytes_prompt("Data")
                out = b64url_encode(data)
                print(out)
                print(f"hex input: {data.hex()}")
            elif choice == "4":
                text = safe_input("b64url: ")
                out = b64url_decode(text)
                show_text_hex(out, "Decoded")
            elif choice == "5":
                token = safe_input("JWT: ")
                parsed = jwt_decode_no_verify(token)
                print(json.dumps(parsed, indent=2))
                print("[!] JWT ini TIDAK diverifikasi signature.")
            elif choice == "6":
                print("[!] Template hanya untuk lab/CTF. Toolkit tidak melakukan auto-scan.")
                for name, payloads in REQUEST_TEMPLATES.items():
                    print(f"\n[{name.upper()}]")
                    for p in payloads:
                        print(f"- {p}")
            else:
                print("[!] Pilihan tidak valid.")
        except ValueError as exc:
            print(f"[!] Error: {exc}")


def forensics_menu() -> None:
    while True:
        print("\n=== Forensics/RE Helpers ===")
        print("[1] File Magic Detect")
        print("[2] Hexdump File")
        print("[3] Entropy File")
        print("[4] Strings Extractor")
        print("[5] PCAP Extractor")
        print("[6] PCAP Notes")
        print("[7] ZIP Recover (corrupted header/trailing)")
        print("[8] JPEG Tools (extract/patch dimensi)")
        print("[9] Caesar Shifter Helper")
        print("[0] Kembali")
        choice = safe_input("Pilih opsi: ").strip()
        if choice == "0":
            return

        path = safe_input("Path file: ").strip() if choice in {"1", "2", "3", "4"} else ""
        data = read_bytes_file(path) if path else b""

        if choice in {"1", "2", "3", "4"} and not data:
            print("[!] File kosong / gagal dibaca.")
            continue

        if choice == "1":
            print(f"[+] File type: {detect_file_magic(data)}")
        elif choice == "2":
            length = int(safe_input("Jumlah byte [default 256]: ").strip() or "256")
            print(hexdump(data[:length]))
        elif choice == "3":
            print(f"[+] Entropy: {shannon_entropy(data):.4f}")
        elif choice == "4":
            min_len = int(safe_input("Min length [default 4]: ").strip() or "4")
            strings_found = extract_printable_strings(data, min_len=min_len)
            for idx, value in enumerate(strings_found[:500], start=1):
                print(f"{idx:03d}. {value}")
            if len(strings_found) > 500:
                print(f"[i] {len(strings_found)-500} hasil lain disembunyikan.")
        elif choice == "5":
            pcap_path = safe_input("Path PCAP/PCAPNG: ").strip()
            output_root = safe_input("Output folder [default output]: ").strip() or "output"
            out_dir = extract_pcap_artifacts(pcap_path, output_root=output_root)
            print(f"[+] Artifact tersimpan di: {out_dir}")
        elif choice == "6":
            print(PCAP_HELP_TEXT)
        elif choice == "7":
            zip_path = safe_input("Path ZIP rusak: ").strip()
            recovered = recover_corrupted_zip(zip_path)
            print(f"[+] ZIP hasil recover: {recovered}")
            try:
                members = list_zip_members(str(recovered))
                print("[+] Isi ZIP:")
                for name in members[:200]:
                    print(f"  - {name}")
                if len(members) > 200:
                    print(f"[i] {len(members)-200} entri lain disembunyikan.")
            except Exception as exc:
                print(f"[!] ZIP belum bisa dibuka: {exc}")
        elif choice == "8":
            print("[1] Extract JPEG fragments")
            print("[2] Lihat dimensi JPEG")
            print("[3] Patch dimensi JPEG")
            sub = safe_input("Pilih opsi: ").strip()
            if sub == "1":
                source = safe_input("Path file sumber: ").strip()
                out_dir = safe_input("Output folder [default output/jpeg_fragments]: ").strip() or "output/jpeg_fragments"
                parts = extract_jpeg_fragments(source, output_dir=out_dir)
                print(f"[+] Fragment ditemukan: {len(parts)}")
                for fragment in parts[:50]:
                    print(f"  - {fragment}")
            elif sub == "2":
                source = safe_input("Path JPEG: ").strip()
                width, height = get_jpeg_dimensions(source)
                print(f"[+] Dimensi: {width}x{height}")
            elif sub == "3":
                source = safe_input("Path JPEG: ").strip()
                width = int(safe_input("Width baru: ").strip())
                height = int(safe_input("Height baru: ").strip())
                patched = patch_jpeg_dimensions(source, width=width, height=height)
                print(f"[+] JPEG patched: {patched}")
            else:
                print("[!] Pilihan tidak valid.")
        elif choice == "9":
            text = safe_input("Ciphertext Caesar: ")
            if not text:
                print("[!] Teks kosong.")
                continue
            top_n = int(safe_input("Tampilkan berapa kandidat? [default 5]: ").strip() or "5")
            for shift, candidate in suggest_caesar_candidates(text, top_n=top_n):
                print(f"[shift {shift:2d}] {candidate}")
        else:
            print("[!] Pilihan tidak valid.")


def show_main_menu() -> None:
    print("\n=== CTF Toolkit CLI ===")
    print("[1] Decode/Encode")
    print("[2] XOR Brute Force")
    print("[3] Regex Flag Finder")
    print("[4] File Scanner / Strings")
    print("[5] HTTP Request Tester")
    print("[6] Simple Wordlist Brute")
    print("[7] Crypto Tools")
    print("[8] BinEx Tools")
    print("[9] Web Helpers (safe)")
    print("[10] Forensics/RE Helpers")
    print("[0] Exit")


def main() -> None:
    while True:
        show_main_menu()
        choice = safe_input("Pilih opsi menu: ").strip()

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
        elif choice == "7":
            crypto_menu()
        elif choice == "8":
            binex_menu()
        elif choice == "9":
            web_helpers_menu()
        elif choice == "10":
            forensics_menu()
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
