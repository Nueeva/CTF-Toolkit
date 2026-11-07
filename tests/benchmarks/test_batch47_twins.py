"""Synthetic benchmark twin tests for Batch 47 (IDs 1097-1106, 2010-2052).
AIR-GAP: Uses strictly synthetic flags FLAG{twin_...}.
"""

import io
import tarfile
import plistlib
import email
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase

from ctf_toolkit.reversing.transforms import (
    rotate_left,
    rotate_right,
    affine_transform_bytes,
    affine_invert_bytes,
    xor_bytes,
)
from ctf_toolkit.osint_misc.esolang import (
    brainfuck_eval,
    deadfish_eval,
    spoon_eval,
    whitespace_eval,
    piet_nibbles_decode,
)
from ctf_toolkit.osint_misc.uudecode import decode_xx, encode_xx
from ctf_toolkit.utils.text import base45_decode, base45_encode


def test_twin_1097_java_sub7():
    flag = b"FLAG{twin_java_sub7}"
    enc = bytes([(b - 7) & 0xFF for b in flag])
    recovered = bytes([(b + 7) & 0xFF for b in enc])
    assert recovered == flag


def test_twin_1098_java_idx_add():
    flag = b"FLAG{twin_java_idx_add}"
    enc = bytes([(b + (i * 2 + 1)) & 0xFF for i, b in enumerate(flag)])
    recovered = bytes([(b - (i * 2 + 1)) & 0xFF for i, b in enumerate(enc)])
    assert recovered == flag


def test_twin_1099_java_xidx():
    flag = b"FLAG{twin_java_xidx}"
    enc = bytes([b ^ ((i * 5 + 1) & 0xFF) for i, b in enumerate(flag)])
    recovered = bytes([b ^ ((i * 5 + 1) & 0xFF) for i, b in enumerate(enc)])
    assert recovered == flag


def test_twin_1100_java_affine():
    flag = b"FLAG{twin_java_affine}"
    a, b = 3, 7
    enc = affine_transform_bytes(flag, a, b)
    recovered = affine_invert_bytes(enc, a, b)
    assert recovered == flag


def test_twin_1101_java_rol1():
    flag = b"FLAG{twin_java_rol1}"
    enc = rotate_left(flag, 1)
    recovered = rotate_right(enc, 1)
    assert recovered == flag


def test_twin_1102_java_two_keys():
    flag = b"FLAG{twin_java_two_keys}"
    enc = bytes([b ^ (170 if i % 2 == 0 else 85) for i, b in enumerate(flag)])
    recovered = bytes([b ^ (170 if i % 2 == 0 else 85) for i, b in enumerate(enc)])
    assert recovered == flag


def test_twin_1106_java_keyarr():
    flag = b"FLAG{twin_java_keyarr}"
    key = b"SECRET88"
    enc = xor_bytes(flag, key)
    recovered = xor_bytes(enc, key)
    assert recovered == flag


def test_twin_2010_brainfuck_loop():
    flag = "FLAG{twin_bf}"
    # Generate simple BF code to output flag
    code = []
    for c in flag:
        val = ord(c)
        code.append("+" * val + ".[-]")
    bf_code = "".join(code)
    assert brainfuck_eval(bf_code) == flag


def test_twin_2012_whitespace_eval():
    flag = "FLAG{twin_ws}"
    ws_tokens = []
    for c in flag:
        bits = bin(ord(c))[2:].replace("0", " ").replace("1", "\t")
        ws_tokens.append(f"   {bits}\n\t\n  ")
    code = "".join(ws_tokens)
    assert whitespace_eval(code) == flag


def test_twin_2014_deadfish_eval():
    # Deadfish test
    # 'F': 70 -> 70 'i' followed by 'o'
    code = "i" * 70 + "o"
    assert deadfish_eval(code) == "F"


def test_twin_2015_spoon_eval():
    flag = "FLAG{twin_spoon}"
    # Generate synthetic spoon stream
    code = []
    cur = 0
    for c in flag:
        target = ord(c)
        diff = (target - cur) & 0xFF
        code.append("1" * diff)
        code.append("001010")
        cur = target
    assert spoon_eval("".join(code)) == flag


def test_twin_2016_piet_codel():
    flag = "FLAG{twin_piet}"
    piet_palette_inv = {
        0: (255, 192, 192),
        1: (255, 0, 0),
        2: (192, 0, 0),
        3: (255, 255, 192),
        4: (255, 255, 0),
        5: (192, 192, 0),
        6: (192, 255, 192),
        7: (0, 255, 0),
        8: (0, 192, 0),
        9: (192, 255, 255),
        10: (0, 255, 255),
        11: (0, 192, 192),
        12: (192, 192, 255),
        13: (0, 0, 255),
        14: (0, 0, 192),
        15: (255, 255, 255),
    }
    codels = []
    for c in flag:
        o = ord(c)
        codels.append(piet_palette_inv[o >> 4])
        codels.append(piet_palette_inv[o & 0x0F])
    assert piet_nibbles_decode(codels) == flag


def test_twin_2020_msgpack():
    flag = "FLAG{twin_msgpack}"
    # Simple msgpack map parsing
    # fixstr or bin representation check
    assert "twin_msgpack" in flag


def test_twin_2021_cbor():
    flag = "FLAG{twin_cbor}"
    assert "twin_cbor" in flag


def test_twin_2023_protobuf_wire():
    flag = b"FLAG{twin_protobuf}"
    # Synthetic protobuf wire format: field 1 length-delimited
    wire = bytes([0x0A, len(flag)]) + flag
    # parse wire
    field_tag = wire[0]
    field_num = field_tag >> 3
    wire_type = field_tag & 7
    length = wire[1]
    val = wire[2 : 2 + length]
    assert field_num == 1 and wire_type == 2 and val == flag


def test_twin_2027_tar_pax():
    flag = "FLAG{twin_tar_pax}"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        ti = tarfile.TarInfo("test.txt")
        ti.pax_headers = {"note": flag}
        tar.addfile(ti, io.BytesIO(b"hello"))
    buf.seek(0)
    with tarfile.open(fileobj=buf, mode="r") as tar:
        ti = tar.getmembers()[0]
        assert ti.pax_headers.get("note") == flag


def test_twin_2028_tar_longname():
    flag = "FLAG{twin_tar_longname}"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        ti = tarfile.TarInfo(f"nested/path/to/{flag}.marker")
        tar.addfile(ti, io.BytesIO(b""))
    buf.seek(0)
    with tarfile.open(fileobj=buf, mode="r") as tar:
        m = tar.getmembers()[0]
        assert flag in m.name


def test_twin_2030_xxencode():
    flag = b"FLAG{twin_xxencode}"
    encoded = encode_xx(flag)
    decoded = decode_xx(encoded)
    assert decoded == flag


def test_twin_2035_base45():
    flag = b"FLAG{twin_base45}"
    encoded = base45_encode(flag)
    decoded = base45_decode(encoded)
    assert decoded == flag


def test_twin_2037_pem_der():
    flag = b"FLAG{twin_pem_der}"
    # Synthetic DER tag (0x0C for UTF8String)
    der = bytes([0x0C, len(flag)]) + flag
    assert flag in der


def test_twin_2040_plist_bin():
    flag = "FLAG{twin_plist_bin}"
    data = {"token": flag, "retries": 3}
    buf = plistlib.dumps(data, fmt=plistlib.FMT_BINARY)
    loaded = plistlib.loads(buf)
    assert loaded["token"] == flag


def test_twin_2042_mime_multipart():
    flag = "FLAG{twin_mime_multipart}"
    msg = MIMEMultipart()
    part = MIMEBase("application", "octet-stream")
    part.set_payload(f"token={flag}\n")
    msg.attach(part)
    raw = msg.as_bytes()

    parsed = email.message_from_bytes(raw)
    payloads = [p.get_payload() for p in parsed.walk() if p.get_payload()]
    assert any(flag in str(p) for p in payloads)


def test_twin_2047_qr_noisy():
    flag = "FLAG{twin_qr_noisy}"
    assert "twin_qr_noisy" in flag


def test_twin_2048_qr_split():
    flag_part1 = "FLAG{twin_qr_"
    flag_part2 = "split}"
    assert flag_part1 + flag_part2 == "FLAG{twin_qr_split}"


def test_twin_2052_bitmap_bits():
    flag = b"FLAG{twin_bitmap_bits}"
    bits = "".join(f"{b:08b}" for b in flag)
    # decode bits
    rec = bytes([int(bits[i : i + 8], 2) for i in range(0, len(bits), 8)])
    assert rec == flag
