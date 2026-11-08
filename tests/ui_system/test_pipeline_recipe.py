from __future__ import annotations

import base64
from ctf_toolkit.pipeline import run_recipe, RecipePipeline


def test_recipe_base64() -> None:
    enc = base64.b64encode(b"CTF{b64_pipeline_test}").decode()
    res = run_recipe("b64d", enc)
    assert res == b"CTF{b64_pipeline_test}"

    enc_again = run_recipe("b64e", res)
    assert enc_again == enc


def test_recipe_hex() -> None:
    hex_str = "48656c6c6f5f576f726c64"
    res = run_recipe("hex_decode", hex_str)
    assert res == b"Hello_World"

    enc_hex = run_recipe("hex_encode", res)
    assert enc_hex == hex_str.lower()


def test_recipe_rot13_and_rot47() -> None:
    res = run_recipe("rot13", "synt{ebg13_grfg}")
    assert res == "flag{rot13_test}"

    res47 = run_recipe("rot47", "7=28#C@Ecf0E6DE%")
    assert "rot47" in res47


def test_recipe_atbash_and_reverse() -> None:
    res = run_recipe("atbash", "uozt")
    assert res == "flag"

    rev = run_recipe("reverse", "12345")
    assert rev == "54321"


def test_recipe_xor() -> None:
    # Single byte XOR with hex literal
    raw = b"flag{xor_pipeline}"
    xored = bytes(b ^ 0x37 for b in raw)
    res = run_recipe("xor:0x37", xored)
    assert res == raw

    # Repeating key XOR with text key
    rep_key = b"LEET"
    rep_xored = bytes(b ^ rep_key[i % len(rep_key)] for i, b in enumerate(raw))
    res_rep = run_recipe("xor:LEET", rep_xored)
    assert res_rep == raw


def test_recipe_rc4() -> None:
    from ctf_toolkit.crypto.rc4 import rc4_crypt
    plain = b"CTF{rc4_stream_cipher}"
    key = b"supersecret"
    cipher = rc4_crypt(key, plain)

    res = run_recipe("rc4:supersecret", cipher)
    assert res == plain


def test_recipe_rle_decode() -> None:
    res = run_recipe("rle_decode", "4A2B1C")
    assert res == "AAAABBC"


def test_recipe_flag_scan() -> None:
    text = "Noise prefix garbage 1234 GETSFLAG{pipeline_scanned} trailer noise"
    res = run_recipe("flag_scan", text)
    assert res == "GETSFLAG{pipeline_scanned}"


def test_recipe_multi_stage_chain() -> None:
    # Construct multi-stage vector:
    # Plain flag -> ROT13 -> Base64 encode -> Hex encode
    plain = "GETSFLAG{multi_stage_recipe_engine_verified}"
    rot13_val = run_recipe("rot13", plain)
    b64_val = base64.b64encode(rot13_val.encode()).decode()
    hex_val = b64_val.encode().hex()

    # Solve using recipe pipeline
    recipe = "hex_decode | b64d | rot13 | flag_scan"
    recovered = run_recipe(recipe, hex_val)
    assert recovered == plain


def test_recipe_invalid_op() -> None:
    try:
        run_recipe("unknown_op_xyz", "data")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Unknown recipe operation" in str(e)
