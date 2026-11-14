"""End-to-end validation of advanced auto-solver & crypto-solver capabilities:
- LFSR / Berlekamp-Massey bitstream challenges
- Diffie-Hellman with smooth p-1 discrete log (Pohlig-Hellman & BSGS)
- Smart's attack on anomalous elliptic curves
- Coppersmith's stereotyped message RSA recovery
- Hash Length Extension automated forgery
- CRC32 target forgery automated detection
"""

from __future__ import annotations

import hashlib
import zlib
import pytest

from ctf_toolkit.crypto.auto_solver import solve_crypto_task
from ctf_toolkit.crypto.dlog_engine import EllipticCurve, ECPoint
from ctf_toolkit.crypto.lfsr import lfsr_generate, bits_to_bytes


def test_auto_solve_lfsr_stream_cipher():
    taps = [1, 1, 0, 0, 1]  # x^4 + x^3 + 1
    flag = b"GETSFLAG{lfsr_auto_solved_1337}"
    bits_gen = lfsr_generate([1, 0, 1, 1], taps, len(flag) * 8 + 32)
    ks = bits_to_bytes(bits_gen)
    ct = bytes(f ^ k for f, k in zip(flag, ks[:len(flag)]))
    leak_bits = "".join(str(b) for b in bits_gen[:32])

    prompt = f"""
    [Crypto] LFSR Keystream recovery
    Observed bits: {leak_bits}
    Ciphertext (hex): {ct.hex()}
    """
    sol = solve_crypto_task(prompt)
    assert sol == "GETSFLAG{lfsr_auto_solved_1337}"


def test_auto_solve_dh_pohlig_hellman():
    p = 120121  # p-1 is 2^3*3*5*7*11*13 smooth
    g = 29
    a_priv = 98765
    A = pow(g, a_priv, p)
    B = pow(g, 4321, p)
    s = pow(B, a_priv, p)

    prompt = f"""
    Diffie-Hellman Key Exchange with smooth order:
    p = {p}
    g = {g}
    A = {A}
    B = {B}
    """
    sol = solve_crypto_task(prompt)
    assert sol == f"GETSFLAG{{{s}}}"


def test_auto_solve_dh_bsgs_small_prime():
    p = 1000003
    g = 2
    a_priv = 12345
    A = pow(g, a_priv, p)
    B = pow(g, 54321, p)
    s = pow(B, a_priv, p)

    prompt = f"DH Challenge: p = {p}, g = {g}, A = {A}, B = {B}"
    sol = solve_crypto_task(prompt)
    assert sol == f"GETSFLAG{{{s}}}"


def test_auto_solve_ecc_smart_anomalous():
    p = 101
    a = 1
    b = 32
    curve = EllipticCurve(a, b, p)
    pts = [ECPoint(x, y) for x in range(p) for y in range(p) if curve.on_curve(ECPoint(x, y))]
    P = pts[3]
    k_priv = 57
    Q = curve.mul(k_priv, P)

    prompt = f"""
    Elliptic Curve Cryptography on Anomalous Curve:
    y^2 = x^3 + {a}*x + {b} (mod {p})
    P = ({P.x}, {P.y})
    Q = ({Q.x}, {Q.y})
    """
    sol = solve_crypto_task(prompt)
    assert sol == f"GETSFLAG{{{k_priv}}}"


def test_auto_solve_coppersmith_stereotyped():
    import sympy
    p = sympy.nextprime(2**128)
    q = sympy.nextprime(p + 100)
    n = p * q
    e = 3
    flag = b"GETSFLAG{78912}"
    m = int.from_bytes(flag, "big")
    c = pow(m, e, n)

    prompt = f"""
    RSA Stereotyped Challenge:
    n = {n}
    e = {e}
    c = {c}
    known = GETSFLAG{{
    """
    sol = solve_crypto_task(prompt)
    assert sol == "GETSFLAG{78912}"


def test_auto_solve_length_extension():
    secret = b"topsecret123"
    msg = b"user=guest"
    app = b"&admin=true"
    leaked = hashlib.sha256(secret + msg).hexdigest()

    prompt = f"""
    Server uses secret-prefix signature: H(secret || msg)
    leaked = {leaked}
    msg = {msg.decode()}
    secret_len = {len(secret)}
    append = {app.decode()}
    """
    sol = solve_crypto_task(prompt)
    from ctf_toolkit.crypto.length_extension import length_extension
    expected_res = length_extension("sha256", len(secret), msg, app, leaked)
    assert sol == f"GETSFLAG{{{expected_res.digest}}}"


def test_auto_solve_crc32_forgery():
    data = b"user=guest&role=user&flag=GETSFLAG{crc32_patch_ok}"
    target = 0xCAFEBABE
    prompt = f"""
    CRC32 collision challenge:
    data = user=guest&role=user&flag=GETSFLAG{{crc32_patch_ok}}
    target = 0x{target:08x}
    """
    sol = solve_crypto_task(prompt)
    assert sol == "GETSFLAG{crc32_patch_ok}"


def test_cascade_dag_lfsr_recovery():
    from ctf_toolkit.crypto.cascade import run_cascade
    taps = [1, 1, 0, 0, 1]
    flag = b"GETSFLAG{cascade_lfsr_pass}"
    bits_gen = lfsr_generate([1, 0, 1, 1], taps, len(flag) * 8 + 32)
    ks = bits_to_bytes(bits_gen)
    ct = bytes(f ^ k for f, k in zip(flag, ks[:len(flag)]))
    leak_bits = "".join(str(b) for b in bits_gen[:32])

    report = {
        "plan": ["stream_lfsr"],
        "source": f"lfsr_stream = '{leak_bits}'",
        "output_text": ct.hex(),
        "output_bytes": ct,
        "params": {},
    }
    res = run_cascade(report)
    assert res.ok() is True
    assert res.flag == "GETSFLAG{cascade_lfsr_pass}"
    assert "lfsr-berlekamp-massey[L=4]" in str(res.matched_source)
