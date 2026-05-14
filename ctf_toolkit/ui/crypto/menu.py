from __future__ import annotations

import binascii

from ctf_toolkit.ui.common import int_to_bytes, print_lks_flag_candidates_from_text, read_bytes_prompt, show_text_hex
from ctf_toolkit.utils.io import safe_input, warn
from ctf_toolkit.utils.menu import run_menu


def custom_alphabet_solver_menu(ciphertext: str) -> None:
    if not ciphertext:
        warn("Teks kosong.")
        return

    from ctf_toolkit.crypto.custom_alphabet import (
        apply_custom_cipher,
        auto_solve_custom_cipher,
        bruteforce_custom_cipher,
        parse_custom_key,
        validate_alphabet,
    )

    try:
        alphabet = validate_alphabet(safe_input("Alphabet custom: "))
        print("[1] Auto shift + XOR (bruteforce)")
        print("[2] Bruteforce shift (custom Caesar)")
        print("[3] Shift dengan key (angka/list)")
        print("[4] Bruteforce XOR index")
        print("[5] XOR dengan key (angka/list)")
        choice = safe_input("Pilih opsi: ").strip()
        if choice == "1":
            results = auto_solve_custom_cipher(ciphertext, alphabet)
            print("\n[Shift bruteforce]")
            for shift, value in results["shift"]:
                print(f"{shift:02d}: {value}")
            print("\n[XOR bruteforce]")
            for shift, value in results["xor"]:
                print(f"{shift:02d}: {value}")
        elif choice in {"2", "4"}:
            mode = "xor" if choice == "4" else "shift"
            for shift, value in bruteforce_custom_cipher(ciphertext, alphabet, mode=mode):
                print(f"{shift:02d}: {value}")
        elif choice in {"3", "5"}:
            mode = "xor" if choice == "5" else "shift"
            key_raw = safe_input("Key (angka pisah koma / string alphabet): ")
            shifts = parse_custom_key(key_raw, alphabet)
            print(apply_custom_cipher(ciphertext, alphabet, shifts, mode=mode))
        else:
            warn("Pilihan tidak valid.")
    except ValueError as exc:
        warn(f"Error: {exc}")


def classical_menu() -> None:
    from ctf_toolkit.crypto.classical import (
        affine_decrypt,
        affine_encrypt,
        apply_substitution,
        atbash,
        caesar_bruteforce,
        caesar_decrypt,
        caesar_encrypt,
        frequency_analysis,
        vigenere_decrypt,
        vigenere_encrypt,
    )

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
        print("[10] Custom Alphabet Cipher Solver")
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
            elif choice == "10":
                custom_alphabet_solver_menu(text)
            else:
                warn("Pilihan tidak valid.")
        except ValueError as exc:
            warn(f"Error: {exc}")


def rsa_menu() -> None:
    from ctf_toolkit.utils.parse import parse_int
    from ctf_toolkit.crypto.rsa import (
        common_modulus_attack,
        fermat_factor,
        hastad_broadcast,
        private_exponent_from_factors,
        rsa_decrypt,
        rsa_encrypt,
    )

    while True:
        print("\n=== Crypto > RSA ===")
        print("[1] Encrypt (m^e mod n)")
        print("[2] Decrypt (c^d mod n)")
        print("[3] Common Modulus Attack")
        print("[4] Hastad Broadcast Attack")
        print("[5] Fermat Factorization")
        print("[6] Hitung d dari faktor prima")
        print("[7] Close-primes RSA Solve (Fermat end-to-end)")
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
            elif choice == "7":
                n = parse_int(safe_input("n (dec/0x): "))
                e = parse_int(safe_input("e (dec/0x): "))
                c = parse_int(safe_input("c (dec/0x): "))
                max_iter = int(safe_input("max_steps [default 50000]: ").strip() or "50000")
                factors = fermat_factor(n, max_iter=max_iter)
                if not factors:
                    print("[-] Faktor tidak ditemukan dalam batas max_steps.")
                    continue
                p, q = factors
                phi = (p - 1) * (q - 1)
                d = private_exponent_from_factors(e, [p, q])
                m = rsa_decrypt(c, n, d)
                m_bytes = int_to_bytes(m)
                text = m_bytes.decode("utf-8", errors="ignore")
                print(f"[+] p: {p}")
                print(f"[+] q: {q}")
                print(f"[+] phi(n): {phi}")
                print(f"[+] d: {d}")
                print(f"[+] plaintext (utf-8 ignore): {text}")
                print(f"[+] plaintext raw bytes: {m_bytes!r}")
                print(f"[+] plaintext bytes (hex): {m_bytes.hex()}")
                print_lks_flag_candidates_from_text(text)
            else:
                warn("Pilihan tidak valid.")
        except ValueError as exc:
            warn(f"Error: {exc}")


def symmetric_menu() -> None:
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

    while True:
        print("\n=== Crypto > Symmetric (AES/Stream) ===")
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
                pt = read_bytes_prompt("Plaintext", safe_input)
                key = read_bytes_prompt("Key", safe_input)
                use_padding = safe_input("Gunakan PKCS#7 padding? [Y/n]: ").strip().lower() != "n"
                show_text_hex(aes_ecb_encrypt(pt, key, use_padding=use_padding), "Ciphertext")
            elif choice == "2":
                ct = read_bytes_prompt("Ciphertext", safe_input)
                key = read_bytes_prompt("Key", safe_input)
                do_unpad = safe_input("Lepas PKCS#7 padding? [Y/n]: ").strip().lower() != "n"
                show_text_hex(aes_ecb_decrypt(ct, key, unpad=do_unpad), "Plaintext")
            elif choice == "3":
                pt = read_bytes_prompt("Plaintext", safe_input)
                key = read_bytes_prompt("Key", safe_input)
                iv = read_bytes_prompt("IV (16 byte)", safe_input)
                use_padding = safe_input("Gunakan PKCS#7 padding? [Y/n]: ").strip().lower() != "n"
                show_text_hex(aes_cbc_encrypt(pt, key, iv, use_padding=use_padding), "Ciphertext")
            elif choice == "4":
                ct = read_bytes_prompt("Ciphertext", safe_input)
                key = read_bytes_prompt("Key", safe_input)
                iv = read_bytes_prompt("IV (16 byte)", safe_input)
                do_unpad = safe_input("Lepas PKCS#7 padding? [Y/n]: ").strip().lower() != "n"
                show_text_hex(aes_cbc_decrypt(ct, key, iv, unpad=do_unpad), "Plaintext")
            elif choice == "5":
                data = read_bytes_prompt("Data", safe_input)
                key = read_bytes_prompt("Key", safe_input)
                nonce = read_bytes_prompt("Nonce (disarankan <=15 byte)", safe_input)
                show_text_hex(aes_ctr_crypt(data, key, nonce), "Output")
            elif choice == "6":
                show_text_hex(pkcs7_pad(read_bytes_prompt("Data", safe_input)), "Padded")
            elif choice == "7":
                show_text_hex(pkcs7_unpad(read_bytes_prompt("Data", safe_input)), "Unpadded")
            elif choice == "8":
                repeats, blocks = detect_ecb(read_bytes_prompt("Ciphertext", safe_input))
                print(f"[+] Block total: {blocks}")
                print(f"[+] Block berulang: {repeats}")
                print("[+] Indikasi ECB kuat." if repeats > 0 else "[-] Tidak ada pengulangan blok mencolok.")
            else:
                warn("Pilihan tidak valid.")
        except (ValueError, binascii.Error) as exc:
            warn(f"Error: {exc}")


def attacks_menu() -> None:
    print("\n=== Crypto > Attacks (CTR Keystream Reuse) ===")

    from ctf_toolkit.crypto.stream_attacks import (
        decrypt_with_partial_keystream,
        keystream_from_known_pair,
        masked_utf8_view,
        merge_keystreams,
    )

    target = read_bytes_prompt("Target ciphertext", safe_input)
    if not target:
        warn("Target ciphertext kosong.")
        return

    pair_count = int(safe_input("Jumlah known pair [minimal 1]: ").strip() or "1")
    if pair_count < 1:
        warn("Jumlah pair harus >= 1.")
        return

    streams: list[bytes] = []
    for idx in range(pair_count):
        print(f"\n--- Known pair #{idx + 1} ---")
        known_ct = read_bytes_prompt("Known ciphertext", safe_input)
        known_pt = read_bytes_prompt("Known plaintext (gunakan raw:... untuk teks)", safe_input)
        if not known_ct or not known_pt:
            warn("Known ciphertext/plaintext tidak boleh kosong.")
            return
        streams.append(keystream_from_known_pair(known_ct, known_pt))

    keystream = merge_keystreams(streams)
    plain, known_mask = decrypt_with_partial_keystream(target, keystream)
    known_count = sum(1 for known in known_mask if known)
    show_masked = safe_input("Tampilkan unknown byte sebagai '.'? [Y/n]: ").strip().lower() != "n"

    print(f"[+] Keystream coverage: {known_count}/{len(target)} byte")
    print(f"[+] Plaintext (hex): {plain.hex()}")
    print(f"[+] Plaintext (utf-8 ignore): {plain.decode('utf-8', errors='ignore')}")
    if show_masked:
        print(f"[+] Plaintext masked: {masked_utf8_view(plain, known_mask, unknown_char='.')}")

    print_lks_flag_candidates_from_text(plain.decode("utf-8", errors="ignore"))


def prng_menu() -> None:
    from ctf_toolkit.utils.parse import parse_int
    from ctf_toolkit.crypto.prng import lcg_generate, recover_lcg_params_known_mod

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
                warn("Pilihan tidak valid.")
        except ValueError as exc:
            warn(f"Error: {exc}")


def hashes_menu() -> None:
    from ctf_toolkit.crypto.hashes import LENGTH_EXTENSION_NOTE, digest

    print("\n=== Crypto > Hashes ===")
    data = read_bytes_prompt("Data", safe_input)
    for algo in ("md5", "sha1", "sha256"):
        print(f"{algo}: {digest(data, algo)}")
    print(f"[i] {LENGTH_EXTENSION_NOTE}")


def custom_menu() -> None:
    from ctf_toolkit.forensics.pyc_decompile import decompile_pyc
    from ctf_toolkit.utils.pager import page_text

    while True:
        print("\n=== Crypto > Custom ===")
        print("[1] Custom Alphabet Shifter (auto shift+XOR)")
        print("[2] Bytecode Decompiler Bridge (.pyc)")
        print("[0] Kembali")
        choice = safe_input("Pilih opsi: ").strip()
        if choice == "0":
            return
        if choice == "1":
            text = safe_input("Ciphertext: ")
            custom_alphabet_solver_menu(text)
        elif choice == "2":
            path = safe_input("Path .pyc: ").strip()
            if not path:
                warn("Path kosong.")
                continue
            try:
                tool, output = decompile_pyc(path)
                print(f"[+] Decompiler: {tool}")
                if not output.strip():
                    warn("Output kosong.")
                    continue
                page_text(output)
            except (ValueError, FileNotFoundError) as exc:
                warn(f"Error: {exc}")
        else:
            warn("Pilihan tidak valid.")


def menu() -> None:
    run_menu(
        "Crypto",
        {
            "1": ("Classical", classical_menu),
            "2": ("RSA", rsa_menu),
            "3": ("Symmetric", symmetric_menu),
            "4": ("PRNG", prng_menu),
            "5": ("Hashes", hashes_menu),
            "6": ("Attacks", attacks_menu),
            "7": ("Custom", custom_menu),
        },
    )
