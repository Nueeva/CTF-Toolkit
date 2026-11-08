from ctf_toolkit.osint_misc.rpn import eval_rpn, eval_rpn_tape
from ctf_toolkit.osint_misc.stego import decode_zero_width, encode_zero_width, decode_trailing_whitespace
from ctf_toolkit.crypto.encoding import rle_decode, rle_encode, normalize_fullwidth


def test_eval_rpn_arithmetic():
    assert eval_rpn("81 10 -") == 71
    assert eval_rpn("21 48 +") == 69
    assert eval_rpn("2 35 *") == 70
    assert eval_rpn("100 25 //") == 4


def test_eval_rpn_tape():
    lines = ["81 10 -", "21 48 +", "90 6 -", "86 3 -"]
    assert eval_rpn_tape(lines) == b"GETS"


def test_zero_width_roundtrip():
    payload = b"GETSFLAG{zw_test}"
    zw = encode_zero_width(payload)
    decoded = decode_zero_width(f"Normal text before {zw} normal text after")
    assert decoded == payload


def test_trailing_whitespace():
    # 71 ('G') = 01000111 -> space tab space space space tab tab tab
    lines = [
        "log line 1 \t   \t\t\t",
        "log line 2 \t   \t\t\t"
    ]
    # first line bits: 01000111 -> 'G'
    assert decode_trailing_whitespace(lines) == b"GG"


def test_rle_roundtrip():
    data = "AAABBBCCCCDD"
    encoded = rle_encode(data)
    assert encoded == "3A3B4C2D"
    assert rle_decode(encoded) == data


def test_normalize_fullwidth():
    fw = "\uff27\uff25\uff34\uff33\uff26\uff2c\uff21\uff27"
    assert normalize_fullwidth(fw) == "GETSFLAG"
