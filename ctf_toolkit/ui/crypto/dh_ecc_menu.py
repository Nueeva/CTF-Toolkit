from __future__ import annotations

from ctf_toolkit.crypto.cipher_id import identify_cipher_text, identify_hash_format
from ctf_toolkit.crypto.dh_ecc_tool import diffie_hellman_compute, ecc_point_operation
from ctf_toolkit.ui.console import console_info
from ctf_toolkit.ui.inspector import inspect_output
from ctf_toolkit.utils.io import safe_input, warn
from ctf_toolkit.utils.menu import run_menu


def dh_ecc_interactive_menu() -> None:
    def dh_action() -> None:
        p_raw = safe_input("p (prima modulus): ").strip()
        g_raw = safe_input("g (generator/base) [default 2]: ").strip() or "2"
        A_raw = safe_input("A = g^a mod p (public Alice, opsional): ").strip()
        B_raw = safe_input("B = g^b mod p (public Bob, opsional): ").strip()
        a_raw = safe_input("a (private Alice, opsional): ").strip()
        b_raw = safe_input("b (private Bob, opsional): ").strip()

        if not p_raw:
            warn("p wajib diisi!")
            return
        try:
            res = diffie_hellman_compute(
                p=int(p_raw, 0),
                g=int(g_raw, 0),
                A=int(A_raw, 0) if A_raw else None,
                B=int(B_raw, 0) if B_raw else None,
                a=int(a_raw, 0) if a_raw else None,
                b=int(b_raw, 0) if b_raw else None,
            )
            inspect_output(res, title="Diffie-Hellman Calculation", op_name="diffie_hellman")
        except Exception as exc:
            warn(f"Error Diffie-Hellman: {exc}")

    def ecc_action() -> None:
        console_info("Elliptic Curve: y^2 = x^3 + a*x + b (mod p)")
        a = int(safe_input("a: ").strip() or "0", 0)
        b = int(safe_input("b: ").strip() or "7", 0)
        p = int(safe_input("p (modulus): ").strip(), 0)
        mode = safe_input("Mode [mul / add, default mul]: ").strip().lower() or "mul"

        Px = int(safe_input("Px: ").strip(), 0)
        Py = int(safe_input("Py: ").strip(), 0)

        if mode == "mul":
            k = int(safe_input("Scalar k: ").strip(), 0)
            res = ecc_point_operation("mul", a, b, p, Px=Px, Py=Py, k=k)
        else:
            Qx = int(safe_input("Qx: ").strip(), 0)
            Qy = int(safe_input("Qy: ").strip(), 0)
            res = ecc_point_operation("add", a, b, p, Px=Px, Py=Py, Qx=Qx, Qy=Qy)

        inspect_output(res, title=f"ECC Point Operation ({mode})", op_name="ecc_point_op")

    run_menu(
        "Diffie-Hellman & Elliptic Curve",
        {
            "1": ("Diffie-Hellman Shared Secret / DLog Crack", dh_action),
            "2": ("Elliptic Curve Point Arithmetic (k*P, P+Q)", ecc_action),
        },
    )


def cipher_identification_menu() -> None:
    text = safe_input("Masukkan ciphertext / hash string: ").strip()
    if not text:
        warn("Input kosong.")
        return
    ciphers = identify_cipher_text(text)
    hashes = identify_hash_format(text)
    out = {
        "text_sample": text[:80] + ("..." if len(text) > 80 else ""),
        "length": len(text),
        "entropy": ciphers.get("entropy"),
        "ioc": ciphers.get("ioc"),
        "cipher_predictions": ciphers.get("likely_types", []),
        "hash_predictions": hashes,
    }
    inspect_output(out, title="Cipher & Hash Identification", op_name="identify_cipher")
