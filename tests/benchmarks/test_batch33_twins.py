from __future__ import annotations

from ctf_toolkit.pipeline import run_recipe
from ctf_toolkit.crypto.encoding import base91_encode, base91_decode, braille_decode, baudot_ita2_decode
from ctf_toolkit.crypto.classical import (
    porta_decrypt,
    columnar_transposition_decrypt,
    rail_fence_decrypt,
    qwerty_shift_decrypt,
    book_cipher_decode,
    variant_beaufort_decrypt,
)


def test_twin_base91_roundtrip() -> None:
    flag = b"CTF{synthetic_base91_stream_benchmark}"
    enc = base91_encode(flag)
    dec = base91_decode(enc)
    assert dec == flag

    # Recipe test
    recipe_dec = run_recipe("b91d", enc)
    assert recipe_dec == flag


def test_twin_porta_and_recipe() -> None:
    # Encrypt a synthetic message with Porta (key = 'CYBER')
    # Because Porta is reciprocal, running porta_decrypt on plaintext produces ciphertext
    plain = "SYNTHETICPORTACIPHERBENCHMARK"
    key = "CYBER"
    cipher = porta_decrypt(plain, key)

    # Decrypt via function
    dec = porta_decrypt(cipher, key)
    assert dec == plain

    # Decrypt via recipe
    rec_dec = run_recipe(f"porta:{key}", cipher)
    assert rec_dec == plain


def test_twin_columnar_transposition() -> None:
    plain = "syntheticcolumnartransposition"
    key = "PYTHON"
    # Columnar encrypt
    num_cols = len(key)
    pad_len = (num_cols - len(plain) % num_cols) % num_cols
    padded = plain + "x" * pad_len
    num_rows = len(padded) // num_cols

    # Read column by column in sorted key order
    order = sorted(range(num_cols), key=lambda i: key[i])
    cols = [padded[c::num_cols] for c in range(num_cols)]
    cipher = "".join(cols[c] for c in order)

    dec = columnar_transposition_decrypt(cipher, key, padding_char="x")
    assert dec == plain


def test_twin_rail_fence_and_recipe() -> None:
    plain = "syntheticrailfencetwintest"
    rails = 4
    # Pattern
    pattern: list[int] = []
    rail, direction = 0, 1
    for _ in range(len(plain)):
        pattern.append(rail)
        rail += direction
        if rail == rails - 1:
            direction = -1
        elif rail == 0:
            direction = 1

    cipher_parts: list[list[str]] = [[] for _ in range(rails)]
    for r, ch in zip(pattern, plain):
        cipher_parts[r].append(ch)
    cipher = "".join("".join(p) for p in cipher_parts)

    dec = rail_fence_decrypt(cipher, rails)
    assert dec == plain

    rec_dec = run_recipe("rail_fence:4", cipher)
    assert rec_dec == plain


def test_twin_qwerty_shift() -> None:
    rows = ("qwertyuiop", "asdfghjkl", "zxcvbnm")
    # Shift right 1
    plain = "synthetic"
    cipher = []
    for c in plain:
        for r in rows:
            if c in r:
                cipher.append(r[(r.index(c) + 1) % len(r)])
                break
    cipher_str = "".join(cipher)

    dec = qwerty_shift_decrypt(cipher_str, steps=-1)
    assert dec == plain


def test_twin_book_cipher() -> None:
    book = "in the realm of cryptography benchmark testing is essential".split()
    target = "benchmark"
    # Target word is book[5] ('benchmark')
    coords = f"6.1 6.2 6.3 6.4 6.5 6.6 6.7 6.8 6.9"
    dec = book_cipher_decode(coords, "in the realm of cryptography benchmark testing is essential")
    assert dec == target


def test_twin_braille_and_baudot() -> None:
    braille_input = "⠎⠽⠝⠞⠓"  # s y n t h
    dec_braille = braille_decode(braille_input)
    assert dec_braille == "synth"

    # Baudot ITA-2: 'TEST'
    # T=16 (10000 -> rev 00001), E=1 (00001 -> rev 10000), S=5 (00101 -> rev 10100), T=16 (10000 -> rev 00001)
    # in little-endian tokens:
    tokens = ["00001", "10000", "10100", "00001"]
    dec_baudot = baudot_ita2_decode(tokens, lsb_first=True)
    assert dec_baudot == "TEST"
