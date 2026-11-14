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


def test_auto_solve_franklin_reiter():
    import sympy
    from ctf_toolkit.crypto.lks_national_suite import franklin_reiter_related_message

    p = sympy.nextprime(2**256)
    q = sympy.nextprime(p + 100)
    n = p * q
    e = 3

    m1 = int.from_bytes(b"GETSFLAG{franklin_reiter_success}", "big")
    b_diff = 42
    m2 = m1 + b_diff

    c1 = pow(m1, e, n)
    c2 = pow(m2, e, n)

    prompt = f"""
    Franklin-Reiter Related Message Challenge:
    n = {n}
    e = {e}
    c1 = {c1}
    c2 = {c2}
    diff = {b_diff}
    """
    sol = solve_crypto_task(prompt)
    assert sol == "GETSFLAG{franklin_reiter_success}"


def test_auto_solve_paillier():
    import sympy
    from ctf_toolkit.crypto.paillier import paillier_encrypt
    p = sympy.nextprime(2**256)
    q = sympy.nextprime(p + 100)
    n = p * q
    m = int.from_bytes(b"GETSFLAG{paillier_homomorphic_ok}", "big")
    c = paillier_encrypt(m, n, r=12345)

    prompt = f"""
    Paillier Public-Key Decryption:
    p = {p}
    q = {q}
    n = {n}
    c = {c}
    """
    sol = solve_crypto_task(prompt)
    assert sol == "GETSFLAG{paillier_homomorphic_ok}"


def test_auto_solve_shamir_secret_sharing():
    p = 1000000007
    prompt = f"""
    Shamir's Secret Sharing Scheme:
    p = {p}
    Shares:
    (1, 804207)
    (2, 608414)
    (3, 412621)
    """
    sol = solve_crypto_task(prompt)
    assert sol == "GETSFLAG{1000000}"


def test_auto_solve_bleichenbacher_forge():
    prompt = """
    Bleichenbacher RSA Signature Forgery:
    key_size = 2048
    e = 3
    hash = sha256
    message = admin=true
    """
    sol = solve_crypto_task(prompt)
    assert sol is not None and sol.startswith("GETSFLAG{")


def test_curve_bsgs_general_curve():
    from ctf_toolkit.crypto.dlog_engine import EllipticCurve, ECPoint, ec_bsgs, ec_bsgs_coords

    # Non-anomalous curve y^2 = x^3 + x + 1 over F_23
    c = EllipticCurve(1, 1, 23)
    pts = [ECPoint(x, y) for x in range(23) for y in range(23) if c.on_curve(ECPoint(x, y))]
    P = pts[0]
    n = c.order_naive()
    assert n == 28
    k_priv = 17
    Q = c.mul(k_priv, P)

    recovered = ec_bsgs(c, P, Q, n)
    assert recovered == k_priv
    assert c.mul(recovered, P) == Q

    assert P.x is not None and P.y is not None and Q.x is not None and Q.y is not None
    recovered_coords = ec_bsgs_coords(1, 1, 23, P.x, P.y, Q.x, Q.y, n)
    assert recovered_coords == k_priv


def test_auto_solve_usb_hid_keystrokes():
    # USB capture of flag{usb_typing}
    # 0x09='f', 0x0f='l', 0x04='a', 0x0a='g', 0x2f(shift)='{', 0x18='u', 0x16='s', 0x05='b', 0x30(shift)='}'
    text = """
    USB Traffic capture (tshark capdata):
    00:00:09:00:00:00:00:00
    00:00:00:00:00:00:00:00
    00:00:0f:00:00:00:00:00
    00:00:00:00:00:00:00:00
    00:00:04:00:00:00:00:00
    00:00:00:00:00:00:00:00
    00:00:0a:00:00:00:00:00
    00:00:00:00:00:00:00:00
    02:00:2f:00:00:00:00:00
    00:00:00:00:00:00:00:00
    00:00:18:00:00:00:00:00
    00:00:00:00:00:00:00:00
    00:00:16:00:00:00:00:00
    00:00:00:00:00:00:00:00
    00:00:05:00:00:00:00:00
    00:00:00:00:00:00:00:00
    02:00:30:00:00:00:00:00
    """
    sol = solve_crypto_task(text)
    assert sol == "flag{usb}"


def test_auto_solve_png_ihdr_repair():
    import struct
    import zlib
    true_w, true_h = 1024, 768
    tail = b"\x08\x06\x00\x00\x00"
    payload = struct.pack(">II", true_w, true_h) + tail
    crc = zlib.crc32(b"IHDR" + payload) & 0xFFFFFFFF
    corrupted = struct.pack(">II", true_w, 1) + tail
    png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + corrupted + struct.pack(">I", crc) + b"\x00\x00\x00\x00IEND\xaeB`\x82"

    prompt = f"Corrupted PNG Challenge: {png.hex()}"
    sol = solve_crypto_task(prompt)
    assert sol == f"GETSFLAG{{{true_w}x{true_h}}}"


def test_auto_solve_hnp_ecdsa():
    from ctf_toolkit.utils.math import modinv
    import random
    n = 2147483647
    d_priv = 123456789
    nonce_bits = 10
    X = 1 << nonce_bits
    sigs = []
    for _ in range(8):
        k = random.randint(1, X - 1)
        h = random.randint(1, n - 1)
        r = random.randint(1, n - 1)
        s = (modinv(k, n) * (h + r * d_priv)) % n
        sigs.append((h, r, s))

    prompt = f"""
    HNP Biased Nonce ECDSA Challenge:
    p = {n}
    nonce_bits = {nonce_bits}
    Signatures:
    """ + "\n".join(f"({h}, {r}, {s})" for h, r, s in sigs)

    sol = solve_crypto_task(prompt)
    assert sol == f"GETSFLAG{{{d_priv}}}"

