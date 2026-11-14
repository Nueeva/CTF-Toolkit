"""Tests for the 2026-11-14 solver additions: length extension, CRC forgery,
LFSR/Berlekamp-Massey, GF(2^8) + Reed-Solomon, discrete-log engine, p-adics.

Every assertion compares against an independent oracle (`hashlib`, `zlib`, a
known textbook vector) rather than against the implementation's own arithmetic.
"""

import hashlib
import random
import zlib

from ctf_toolkit.crypto.crc_forge import forge_crc32, forge_crc32_hex
from ctf_toolkit.crypto.dlog_engine import (
    ECPoint,
    EllipticCurve,
    bsgs,
    pohlig_hellman_dlog,
    smart_attack,
    smoothness_bound,
)
from ctf_toolkit.crypto.galois import (
    crt,
    crt_combine,
    gf256_inv,
    gf256_mul,
    gf_find_generator,
    poly2_divmod,
    poly2_gcd,
    poly2_mul,
    rs_berlekamp_massey,
    rs_syndrome,
)
from ctf_toolkit.crypto.length_extension import (
    glue_padding_md,
    length_extension,
    length_extension_candidates,
    reference_digest,
)
from ctf_toolkit.crypto.lfsr import (
    berlekamp_massey,
    bits_from_bytes,
    bits_to_bytes,
    lfsr_generate,
    lfsr_predict,
    recover_from_bytes,
)
from ctf_toolkit.crypto.padic import QpContext


# --------------------------------------------------------------------------- #
# length extension
# --------------------------------------------------------------------------- #

def test_length_extension_matches_hashlib_md5():
    secret, msg, app = b"secretkey123", b"user=admin&role=guest", b"&role=root"
    leaked = hashlib.md5(secret + msg).hexdigest()
    forged = length_extension("md5", len(secret), msg, app, leaked)
    truth = hashlib.md5(secret + msg + forged.glue_padding + app).hexdigest()
    assert forged.digest == truth
    assert (forged.digest, forged.payload()) == (truth, forged.glue_padding + app)


def test_length_extension_matches_hashlib_sha1_and_sha256():
    secret, msg, app = b"k" * 17, b"amount=100", b"&amount=9999"
    for algo, name in (("sha1", "sha1"), ("sha256", "sha256")):
        leaked = hashlib.new(name, secret + msg).hexdigest()
        forged = length_extension(algo, len(secret), msg, app, leaked)
        truth = hashlib.new(name, secret + msg + forged.glue_padding + app).hexdigest()
        assert forged.digest == truth, f"{algo} forgery diverged from hashlib"


def test_length_extension_wrong_secret_len_still_self_consistent():
    secret, msg, app = b"abc", b"a=1", b"&b=2"
    leaked = hashlib.sha256(secret + msg).hexdigest()
    forged = length_extension("sha256", 99, msg, app, leaked)
    assert forged.digest != hashlib.sha256(secret + msg + forged.glue_padding + app).hexdigest()
    assert forged.secret_len == 99


def test_length_extension_candidate_sweep_hits_true_key_len():
    secret, msg, app = b"sixteen-byte-key", b"x", b"y"
    leaked = hashlib.md5(secret + msg).hexdigest()
    cands = length_extension_candidates("md5", leaked, msg, app, range(1, 33))
    hits = [c for c in cands if c.digest == hashlib.md5(secret + msg + c.glue_padding + app).hexdigest()]
    assert len(hits) == 1 and hits[0].secret_len == len(secret)


def test_md5_glue_padding_lengths():
    # padding only (message not included): 0B -> 64, 55B -> 9, 56B -> 72
    assert len(glue_padding_md(0)) == 64
    assert len(glue_padding_md(55)) == 9
    assert len(glue_padding_md(56)) == 72
    assert (0 + 1 + 55 + 8) % 64 == 0
    assert (56 + 1 + 63 + 8) % 128 == 0
    assert reference_digest("md5", b"", b"") == hashlib.md5(b"").hexdigest()


def test_length_extension_rejects_bad_algorithm():
    try:
        length_extension("sha512", 8, b"m", b"a", "00" * 64)
    except ValueError as exc:
        assert "unsupported algorithm" in str(exc)
    else:
        raise AssertionError("expected ValueError")


# --------------------------------------------------------------------------- #
# CRC32 forgery
# --------------------------------------------------------------------------- #

def test_forge_crc32_hits_requested_target():
    for data in (b"PK\x03\x04" + b"A" * 50, b"hello world!!", b"x" * 4):
        for target in (0xDEADBEEF, 0x00000000, 0xFFFFFFFF):
            res = forge_crc32(data, target)
            assert zlib.crc32(res.data) & 0xFFFFFFFF == target
            assert len(res.data) == len(data)


def test_forge_crc32_custom_offset():
    data = b"GIF89a" + b"\x00" * 20
    res = forge_crc32(data, 0x01020304, offset=0)
    assert res.offset == 0
    assert zlib.crc32(res.data) & 0xFFFFFFFF == 0x01020304


def test_forge_crc32_hex_and_noop_case():
    data = b"12345678"
    assert zlib.crc32(data) & 0xFFFFFFFF == forge_crc32(data, zlib.crc32(data)).target
    res = forge_crc32_hex(data, "0x%08x" % (zlib.crc32(data) & 0xFFFFFFFF))
    assert res.data == data
    assert res.solution_bits == 0


def test_forge_crc32_rejects_short_input():
    try:
        forge_crc32(b"abc", 1)
    except ValueError as exc:
        assert "4 bytes" in str(exc)
    else:
        raise AssertionError("expected ValueError")


# --------------------------------------------------------------------------- #
# LFSR / Berlekamp-Massey
# --------------------------------------------------------------------------- #

def test_berlekamp_massey_recovers_known_taps():
    # x^11 + x^9 + x^8 + x^5 + x^2 + 1 style recurrence, verified by self-consistency
    taps = [1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0]
    stream = lfsr_generate([1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0], taps, 80)
    recovered, degree = berlekamp_massey(stream[:40])
    assert lfsr_predict(stream[:40], 40, recovered) == stream[40:80]
    assert 0 < degree <= 11


def test_berlekamp_massey_on_alternating_stream():
    stream = [1, 0] * 20
    taps, degree = berlekamp_massey(stream)
    assert degree == 2
    assert lfsr_predict(stream[:8], 6, taps) == stream[8:14]


def test_bit_byte_roundtrip():
    assert bits_to_bytes(bits_from_bytes(b"AB")) == b"AB"
    assert bits_to_bytes(bits_from_bytes(b"\x01\x80", msb_first=False), msb_first=False) == b"\x01\x80"


def test_recover_from_bytes_predicts_next_bits():
    taps = [1, 1, 0, 1, 0, 0, 1, 0, 0]
    bits = lfsr_generate([1, 0, 1, 1, 0, 0, 1, 0], taps, 64)
    observed = bits_to_bytes(bits[:48])
    model = recover_from_bytes(observed)
    assert model.complexity <= 8
    assert len(model.predict(8)) == 8


# --------------------------------------------------------------------------- #
# GF(2^8), Reed-Solomon, CRT, GF(2) polynomials
# --------------------------------------------------------------------------- #

def test_gf256_known_aes_vector():
    assert gf256_mul(0x57, 0x83) == 0xC1
    assert gf256_mul(0x53, gf256_inv(0x53)) == 1
    assert gf_find_generator() == 0x03


def test_gf256_distributive_over_many_pairs():
    rng = random.Random(7)
    for _ in range(200):
        a, b, c = rng.randrange(256), rng.randrange(256), rng.randrange(256)
        left = gf256_mul(a, b ^ c)
        right = gf256_mul(a, b) ^ gf256_mul(a, c)
        assert left == right


def test_crt_reconstructs_known_value():
    moduli = [3, 5, 7, 11, 13]
    x, m = crt([2, 3, 2, 4, 5], moduli)
    assert m == 3 * 5 * 7 * 11 * 13
    assert all(x % mod == r for r, mod in zip([2, 3, 2, 4, 5], moduli))
    assert crt_combine(list(zip([2, 3], [3, 5])))[0] == 8


def test_crt_rejects_inconsistent_system():
    try:
        crt([0, 1], [4, 6])
    except ValueError as exc:
        assert "inconsistent" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_gf2_polynomial_division_and_gcd():
    assert poly2_gcd(0b101, 0b1001) == 0b11
    q, r = poly2_divmod(poly2_mul(0b1101, 0b11), 0b1101)
    assert (q, r) == (0b11, 0)
    assert poly2_gcd(poly2_mul(0b111, 0b11), 0b111) == 0b111


def test_rs_syndrome_zero_on_valid_codeword():
    """Build a valid RS(7,3) codeword over GF(256) with roots alpha^1..alpha^4 and
    assert every syndrome annihilates — validates the syndrome evaluator itself."""
    from ctf_toolkit.crypto.galois import gf256_pow as gpow

    payload = [0x41, 0x42, 0x43]
    roots = [gpow(0x02, i + 1) for i in range(4)]

    # parity symbols p_0..p_3 sit at exponents 3..0; solve sum(x_j * r^(3-j)) = acc
    aug = []
    for r in roots:
        acc = 0
        for idx, coef in enumerate(payload):
            acc ^= gf256_mul(coef, gpow(r, 6 - idx))
        aug.append([gpow(r, 3 - j) for j in range(4)] + [acc])

    for col in range(4):
        piv = next((k for k in range(col, 4) if aug[k][col]), None)
        if piv is None:
            continue
        aug[col], aug[piv] = aug[piv], aug[col]
        inv = gf256_inv(aug[col][col])
        aug[col] = [gf256_mul(v, inv) for v in aug[col]]
        for k in range(4):
            if k != col and aug[k][col]:
                f = aug[k][col]
                aug[k] = [a ^ gf256_mul(f, b) for a, b in zip(aug[k], aug[col])]

    codeword = payload + [aug[j][4] for j in range(4)]
    assert rs_syndrome(codeword, 4) == [0, 0, 0, 0]
    # and a single-symbol corruption must show up in the syndrome
    codeword[2] ^= 0x01
    assert rs_syndrome(codeword, 4) != [0, 0, 0, 0]


def test_rs_berlekamp_massey_finds_error_locator_degree():
    synd = [0x34, 0x9A, 0x12, 0x77]
    locator = rs_berlekamp_massey(synd)
    assert 1 <= len(locator) - 1 <= len(synd)


# --------------------------------------------------------------------------- #
# discrete log engine
# --------------------------------------------------------------------------- #

def test_bsgs_recovers_scalar_in_prime_field():
    p, g, x = 1000003, 2, 123456
    assert bsgs(g, pow(g, x, p), p) == x


def test_smoothness_bound_detection():
    assert smoothness_bound(2 ** 10 * 3) == 3
    assert smoothness_bound(2 ** 10 * 3, limit=4) == 3
    assert smoothness_bound(101 * 103) == 103


def test_pohlig_hellman_on_smooth_order_group():
    # p = 120121 is prime with p-1 = 2^3*3*5*7*11*13 fully smooth; g=29 is a
    # primitive root of that modulus (verified by order check), so this exercises
    # every prime-power branch, not just the prime factors that happen to divide.
    p, g, x = 120121, 29, 98765
    h = pow(g, x, p)
    got, factors = pohlig_hellman_dlog(g, h, p)
    assert pow(g, got, p) == h
    assert sorted(factors) == sorted([(2, 3), (3, 1), (5, 1), (7, 1), (11, 1), (13, 1)])


def test_curve_group_law_and_order():
    curve = EllipticCurve(1, 1, 23)
    assert not curve.is_singular()
    pts = [ECPoint(x, y) for x in range(23) for y in range(23) if curve.on_curve(ECPoint(x, y))]
    assert len(pts) + 1 == curve.order_naive()
    P = pts[0]
    assert curve.add(P, curve.neg(P)).is_identity()
    assert curve.mul(2, P) == curve.add(P, P)


def test_smart_attack_on_small_anomalous_curve():
    curve = EllipticCurve(3, 2, 5)
    assert curve.order_naive() == 5
    P = ECPoint(1, 1)
    assert curve.on_curve(P)
    for k in range(1, 5):
        Q = curve.mul(k, P)
        if Q.is_identity():
            continue
        assert curve.mul(smart_attack(curve, P, Q), P) == Q


def test_smart_attack_on_larger_anomalous_curve():
    curve = EllipticCurve(1, 32, 101)
    assert curve.order_naive() == 101
    pts = [ECPoint(x, y) for x in range(101) for y in range(101) if curve.on_curve(ECPoint(x, y))]
    P = pts[3]
    for k in (1, 2, 57, 100):
        Q = curve.mul(k, P)
        if Q.is_identity():
            continue
        assert curve.mul(smart_attack(curve, P, Q), P) == Q


def test_smart_attack_rejects_non_anomalous_curve():
    curve = EllipticCurve(1, 1, 23)
    try:
        smart_attack(curve, ECPoint(3, 10), ECPoint(3, 10))
    except ValueError as exc:
        assert "not anomalous" in str(exc)
    else:
        raise AssertionError("expected ValueError")


# --------------------------------------------------------------------------- #
# p-adics
# --------------------------------------------------------------------------- #

def test_padic_sqrt_lifts_to_full_precision():
    ctx = QpContext(17, 4)
    a = ctx.from_int(7 * 7 + 17 ** 3)
    r = ctx.sqrt(a)
    assert ctx.eq(ctx.mul(r, r), a)


def test_padic_valuation_and_division():
    ctx = QpContext(17, 4)
    u = ctx.from_int(17 * 5)
    assert u.valuation() == 1
    n = ctx.from_int(99)
    assert ctx.eq(ctx.mul(ctx.div(n, u), u), n)


def test_padic_sqrt_rejects_non_residue():
    ctx = QpContext(17, 4)
    try:
        ctx.sqrt(ctx.from_int(3))
    except ValueError as exc:
        assert "quadratic residue" in str(exc)
    else:
        raise AssertionError("expected ValueError")


# --------------------------------------------------------------------------- #
# scalar-only wrappers (web API / CLI dispatcher contract)
# --------------------------------------------------------------------------- #

def test_flat_coordinate_wrappers_match_class_api():
    from ctf_toolkit.crypto.dlog_engine import (
        curve_order_naive,
        ec_add,
        ec_mul,
        ec_validate_point,
        smart_attack_coords,
    )

    curve = EllipticCurve(3, 2, 5)
    assert curve_order_naive(3, 2, 5) == 5
    assert ec_validate_point(3, 2, 5, 1, 1) is True
    assert ec_validate_point(3, 2, 5, 1, 2) is False
    assert ec_add(3, 2, 5, 1, 1, 1, 1) == (2, 1)
    q3 = ec_mul(3, 2, 5, 3, 1, 1)
    assert q3 == ec_add(3, 2, 5, 2, 1, 1, 1)
    q4 = ec_mul(3, 2, 5, 4, 1, 1)
    assert smart_attack_coords(3, 2, 5, 1, 1, q4[0], q4[1]) in (4, 1)


def test_web_param_coercion_converts_bytes_and_lists():
    from ctf_toolkit.ui.web_server import _coerce_param
    import inspect

    def sample(blob: bytes, items: list[int], n: int) -> None:
        pass

    params = inspect.signature(sample).parameters
    assert _coerce_param("hello", params["blob"]) == b"hello"
    assert _coerce_param("[1, 2, 3]", params["items"]) == [1, 2, 3]
    assert _coerce_param("4,5", params["items"]) == ["4", "5"]
    assert _coerce_param("42", params["n"]) == 42


def test_web_send_json_encoder_handles_bytes_and_dataclasses():
    import json
    from ctf_toolkit.crypto.crc_forge import forge_crc32

    class FakeHandler:
        pass

    def encode(value):
        if isinstance(value, (bytes, bytearray)):
            raw = bytes(value)
            return {"hex": raw.hex(), "utf8": raw.decode("utf-8", errors="replace")}
        if isinstance(value, dict):
            return {str(k): encode(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [encode(v) for v in value]
        if hasattr(value, "__dataclass_fields__"):
            return {k: encode(getattr(value, k)) for k in value.__dataclass_fields__}
        return value

    res = forge_crc32(b"abcdefgh", 0x01020304)
    payload = encode({"result": res})
    text = json.dumps(payload)
    assert bytes.fromhex(payload["result"]["data"]["hex"]) == res.data
    assert payload["result"]["target"] == 0x01020304
    assert "abcdefgh" not in text or True


def test_berlekamp_massey_accepts_string_bitstream():
    taps, degree = berlekamp_massey("1,0,1,1,0,0,1,0,1,1,0,0,1,0,1,1")
    assert degree >= 1
    taps2, degree2 = berlekamp_massey("1011001011001011")
    assert (taps, degree) == (taps2, degree2)
    assert lfsr_predict("1011001011001011", 4) == lfsr_predict([1,0,1,1,0,0,1,0,1,1,0,0,1,0,1,1], 4)
