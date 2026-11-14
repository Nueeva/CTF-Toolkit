"""TUI panel for the hash/CRC/LFSR/GF/dlog toolset added 2026-11-14."""

from __future__ import annotations

import hashlib
import zlib

from ctf_toolkit.utils.io import safe_input, warn
from ctf_toolkit.utils.menu import run_menu


def _prompt_bytes(label: str) -> bytes:
    from ctf_toolkit.utils.parse import parse_bytes

    return parse_bytes(safe_input(f"{label} (prefix hex:/b64:/raw:, default auto): "))


def _length_extension_action() -> None:
    from ctf_toolkit.crypto.length_extension import (
        length_extension,
        length_extension_candidates,
    )

    algo = (safe_input("Algoritma [md5/sha1/sha256]: ").strip() or "md5").lower()
    leaked = safe_input("Digest bocor dari H(secret||msg): ").strip()
    msg = _prompt_bytes("Message (tanpa secret)")
    append = _prompt_bytes("Append payload")
    try:
        if safe_input("Sweep panjang secret? [y/N]: ").strip().lower() == "y":
            candidates = length_extension_candidates(algo, leaked, msg, append)
            print(f"[+] {len(candidates)} kandidat; verifikasi tiap payload di server target")
            for cand in candidates[:8]:
                print(f"  len={cand.secret_len:2d} digest={cand.digest}")
            print(f"  ... {len(candidates)} total")
            return
        secret_len = int(safe_input("Panjang secret (byte): ").strip() or "0")
        res = length_extension(algo, secret_len, msg, append, leaked)
        print(f"[+] Forged digest : {res.digest}")
        print(f"[+] Glue padding  : {res.glue_padding.hex()}")
        print(f"[+] Message bytes : {len(res.forged_message)}B")
        print(f"[+] Wire payload  : {res.payload().hex()}")
    except ValueError as exc:
        warn(f"Error: {exc}")


def _crc_forge_action() -> None:
    from ctf_toolkit.crypto.crc_forge import forge_crc32

    data = _prompt_bytes("Data (>= 4 byte)")
    target_raw = safe_input("Target CRC32 (hex, mis. deadbeef): ").strip()
    off_raw = safe_input("Offset window (kosong = 4 byte terakhir): ").strip()
    try:
        target = int(target_raw, 16)
        offset = int(off_raw) if off_raw else None
        res = forge_crc32(data, target, offset)
        print(f"[+] Patched window @{res.offset}: {res.patched_window.hex()}")
        print(f"[+] crc32(data') = {zlib.crc32(res.data) & 0xFFFFFFFF:08x}")
        print(f"[+] Output hex    : {res.data.hex()}")
    except ValueError as exc:
        warn(f"Error: {exc}")


def _lfsr_action() -> None:
    from ctf_toolkit.crypto.lfsr import (
        berlekamp_massey,
        bits_from_bytes,
        bits_to_bytes,
        lfsr_predict,
    )

    data = _prompt_bytes("Bitstream observasi")
    count = int(safe_input("Prediksi berapa bit: ").strip() or "32")
    try:
        bits = bits_from_bytes(data)
        taps, degree = berlekamp_massey(bits)
        predicted = lfsr_predict(bits, count, taps)
        print(f"[+] Linear complexity L = {degree}")
        print(f"[+] Tap polynomial bits  = {''.join(str(t) for t in taps[1:])}")
        print(f"[+] Next {count} bits     = {''.join(str(b) for b in predicted)}")
        print(f"[+] As bytes             = {bits_to_bytes(predicted).hex()}")
    except ValueError as exc:
        warn(f"Error: {exc}")


def _gf_action() -> None:
    from ctf_toolkit.crypto.galois import (
        crt,
        gf256_inv,
        gf256_mul,
        gf_find_generator,
        poly2_gcd,
        rs_syndrome,
        rs_berlekamp_massey,
    )

    print("[1] GF(2^8) multiply/inverse")
    print("[2] Integer CRT")
    print("[3] GF(2) polynomial gcd")
    print("[4] Reed-Solomon syndromes + error locator")
    print("[0] Kembali")
    sub = safe_input("Pilih: ").strip()
    try:
        if sub == "1":
            a = int(safe_input("a (hex): ").strip(), 16)
            b = int(safe_input("b (hex): ").strip(), 16)
            print(f"[+] a*b   = {gf256_mul(a, b):02x}")
            print(f"[+] a^-1  = {gf256_inv(a):02x}")
            print(f"[+] gen   = {gf_find_generator():02x}")
        elif sub == "2":
            rs = [int(x) for x in safe_input("Residues (koma): ").split(",") if x.strip()]
            ms = [int(x) for x in safe_input("Moduli (koma): ").split(",") if x.strip()]
            x, m = crt(rs, ms)
            print(f"[+] x = {x}")
            print(f"[+] M = {m}")
        elif sub == "3":
            a = int(safe_input("poly a (biner): ").strip(), 2)
            b = int(safe_input("poly b (biner): ").strip(), 2)
            print(f"[+] gcd = {bin(poly2_gcd(a, b))}")
        elif sub == "4":
            cw = _prompt_bytes("Codeword")
            nsym = int(safe_input("Jumlah syndrome: ").strip() or "4")
            synd = rs_syndrome(list(cw), nsym)
            locator = rs_berlekamp_massey(synd)
            print(f"[+] Syndromes  = {[f'{s:02x}' for s in synd]}")
            print(f"[+] Locator    = {[f'{c:02x}' for c in locator]}")
            print(f"[+] Error count= {len(locator) - 1}")
        else:
            warn("Pilihan tidak valid.")
    except (ValueError, ZeroDivisionError) as exc:
        warn(f"Error: {exc}")


def _dlog_action() -> None:
    from ctf_toolkit.crypto.dlog_engine import (
        ECPoint,
        EllipticCurve,
        bsgs,
        pohlig_hellman_dlog,
        smart_attack,
    )

    print("[1] BSGS (g^x = h mod p)")
    print("[2] Pohlig-Hellman (p-1 smooth)")
    print("[3] Smart's attack (kurva anomalous)")
    print("[0] Kembali")
    sub = safe_input("Pilih: ").strip()
    try:
        if sub == "1":
            p = int(safe_input("p: "))
            g = int(safe_input("g: "))
            h = int(safe_input("h: "))
            order_raw = safe_input("order grup (kosong = p-1): ").strip()
            x = bsgs(g, h, p, int(order_raw) if order_raw else None)
            print(f"[+] x = {x}")
            print(f"[+] Check: g^x == h -> {pow(g, x, p) == h % p}")
        elif sub == "2":
            p = int(safe_input("p: "))
            g = int(safe_input("g: "))
            h = int(safe_input("h: "))
            x, factors = pohlig_hellman_dlog(g, h, p)
            print(f"[+] x = {x}")
            print(f"[+] Faktor p-1 = {factors}")
            print(f"[+] Check: {pow(g, x, p) == h % p}")
        elif sub == "3":
            a = int(safe_input("a: "))
            b = int(safe_input("b: "))
            p = int(safe_input("p: "))
            px, py = int(safe_input("P.x: ")), int(safe_input("P.y: "))
            qx, qy = int(safe_input("Q.x: ")), int(safe_input("Q.y: "))
            curve = EllipticCurve(a, b, p)
            k = smart_attack(curve, ECPoint(px, py), ECPoint(qx, qy))
            print(f"[+] #E = {curve.order_naive()} (p = {p})")
            print(f"[+] k  = {k}")
            print(f"[+] Check: k*P == Q -> {curve.mul(k, ECPoint(px, py)) == ECPoint(qx, qy)}")
        else:
            warn("Pilihan tidak valid.")
    except (ValueError, ZeroDivisionError) as exc:
        warn(f"Error: {exc}")


def deep_crypto_menu() -> None:
    run_menu(
        "Crypto > Deep Solvers",
        {
            "1": ("Hash Length Extension (MD5/SHA1/SHA256)", _length_extension_action),
            "2": ("CRC32 Forgery (patch 4 byte)", _crc_forge_action),
            "3": ("LFSR / Berlekamp-Massey", _lfsr_action),
            "4": ("GF(2^8) & Reed-Solomon & CRT", _gf_action),
            "5": ("Discrete Log (BSGS / Pohlig-Hellman / Smart)", _dlog_action),
        },
    )


_ = hashlib  # re-exported for tests that monkeypatch the panel
