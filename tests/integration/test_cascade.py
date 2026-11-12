import os
import tempfile

from ctf_toolkit.crypto.ast_tracer import trace_directory
from ctf_toolkit.crypto.cascade import run_cascade
from ctf_toolkit.crypto.pure_aes import (
    aes_decrypt_cbc,
    aes_decrypt_ecb,
    aes_encrypt_cbc,
    aes_encrypt_ecb,
)

FLAG_RE = r"FLAG\{[^}]+\}"


def _challenge(tmp: str, script: str, output: str | bytes, name: str = "output.txt") -> str:
    with open(os.path.join(tmp, "chall.py"), "w") as fh:
        fh.write(script)
    mode = "wb" if isinstance(output, bytes) else "w"
    with open(os.path.join(tmp, name), mode) as fh:
        fh.write(output)
    return tmp


# --- AES known-answer -------------------------------------------------------

def test_aes_ecb_known_answer():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert aes_encrypt_ecb(pt, key)[:16] == ct
    assert aes_decrypt_ecb(ct, key) == pt


def test_aes_cbc_roundtrip():
    key = bytes(range(16))
    iv = bytes(range(16, 32))
    msg = b"FLAG{cbc_roundtrip}"
    assert aes_decrypt_cbc(aes_encrypt_cbc(msg, key, iv), key, iv).startswith(msg)


# --- cascade end to end -----------------------------------------------------

def test_cascade_solves_fermat_rsa():
    p, q = 30000000000000053, 30000000000000071
    n = p * q
    e = 65537
    m = int.from_bytes(b"FLAG{fermat}", "big")
    c = pow(m, e, n)
    with tempfile.TemporaryDirectory() as tmp:
        _challenge(
            tmp,
            "n = p * q\nc = pow(m, e, n)\nprint(n, e, c)\n",
            f"n = {n}\ne = {e}\nc = {c}\n",
        )
        res = run_cascade(trace_directory(tmp), flag_pattern=FLAG_RE, total_seconds=10)
    assert res.ok()
    assert res.flag == "FLAG{fermat}"


def test_cascade_solves_small_e_cube_root():
    p = 1000978786087599279142239771599215043648822151851
    q = 2829831743583576611445782142353750403076187393953
    n = p * q
    m = int.from_bytes(b"FLAG{root}", "big")
    c = m ** 3
    assert c < n
    with tempfile.TemporaryDirectory() as tmp:
        _challenge(tmp, "c = pow(m, 3, n)\n", f"n = {n}\nc = {c}\n")
        res = run_cascade(trace_directory(tmp), flag_pattern=FLAG_RE, total_seconds=10)
    assert res.ok()
    assert res.flag == "FLAG{root}"


def test_cascade_solves_single_byte_xor():
    payload = bytes(b ^ 0x5A for b in b"FLAG{xor_here}")
    with tempfile.TemporaryDirectory() as tmp:
        _challenge(tmp, "enc = bytes([b ^ 0x5a for b in flag])\n", payload, name="output.bin")
        res = run_cascade(trace_directory(tmp), flag_pattern=FLAG_RE, total_seconds=10)
    assert res.ok()
    assert res.flag == "FLAG{xor_here}"


def test_cascade_solves_aes_cbc_with_literal_key():
    key = bytes(range(16))
    iv = bytes(range(16, 32))
    ct = aes_encrypt_cbc(b"FLAG{aes_literal}", key, iv)
    script = (
        "from Crypto.Cipher import AES\n"
        "key = bytes(range(16))\n"
        "iv = bytes(range(16, 32))\n"
        "ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(flag, 16))\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        _challenge(tmp, script, f"ciphertext = {ct.hex()}\n")
        res = run_cascade(trace_directory(tmp), flag_pattern=FLAG_RE, total_seconds=10)
    assert res.ok()
    assert res.flag == "FLAG{aes_literal}"


def test_cascade_reports_attempts_even_when_unsolved():
    with tempfile.TemporaryDirectory() as tmp:
        _challenge(tmp, "n = 91\nc = 3\n", "n = 91\ne = 5\nc = 3\n")
        res = run_cascade(trace_directory(tmp), flag_pattern=FLAG_RE, total_seconds=5)
    assert not res.ok()
    assert res.attempts
    assert any(a["solver"] == "rsa_fermat" for a in res.attempts)


def test_cascade_survives_missing_output_file():
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "chall.py"), "w") as fh:
            fh.write("n = 91\n")
        res = run_cascade(trace_directory(tmp), flag_pattern=FLAG_RE, total_seconds=5)
    assert not res.ok()
    assert res.stopped_reason


def test_encoding_peel_recovers_stacked_layers():
    import base64
    import codecs

    inner = "FLAG{peel_me}"
    layer = codecs.encode(inner, "rot13")
    wrapped = base64.b64encode(layer.encode()).decode()
    with tempfile.TemporaryDirectory() as tmp:
        _challenge(tmp, "print(encoded)\n", wrapped)
        res = run_cascade(trace_directory(tmp), flag_pattern=FLAG_RE, total_seconds=10)
    assert res.ok()
    assert res.flag == "FLAG{peel_me}"
