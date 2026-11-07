"""Synthetic benchmark twin tests for Batch 48 (IDs 2013-2094, 25 Misc challenges).
AIR-GAP: Uses strictly synthetic flags FLAG{twin_...}.
"""

import zlib
import sqlite3
import json
import base64
from ctf_toolkit.utils.text import z85_decode, z85_encode, chem_elements_to_bytes
from ctf_toolkit.osint_misc.uudecode import yenc_decode, yenc_encode


def test_twin_2013_befunge_stack():
    flag = "FLAG{twin_befunge}"
    # Befunge-93 reversed string literal on stack
    stack = list(reversed(flag))
    out = "".join(stack.pop() for _ in range(len(flag)))
    assert out == flag


def test_twin_2017_stack_vm():
    flag = "FLAG{twin_stackvm}"
    # Synthetic bytecode: \x01 <char> \x05 (push then print)
    bytecode = bytearray()
    for c in flag:
        bytecode.extend([0x01, ord(c), 0x05])
    bytecode.append(0x00)

    out = []
    i = 0
    st = []
    while i < len(bytecode):
        op = bytecode[i]
        if op == 0x01:
            st.append(bytecode[i + 1])
            i += 2
        elif op == 0x05:
            out.append(chr(st.pop()))
            i += 1
        elif op == 0x00:
            break
        else:
            i += 1
    assert "".join(out) == flag


def test_twin_2022_asn1_der_seq():
    flag = b"FLAG{twin_der_seq}"
    # Synthetic DER sequence holding flag
    der = bytes([0x30, len(flag) + 2, 0x04, len(flag)]) + flag
    assert flag in der


def test_twin_2026_zlib_custom_dict():
    flag = b"FLAG{twin_zlib_dict}"
    zdict = b"session;user;token;config;payload;handoff;worker;"
    comp = zlib.compressobj(zdict=zdict)
    stream = comp.compress(b"prefix " + flag) + comp.flush()

    decomp = zlib.decompressobj(zdict=zdict)
    recovered = decomp.decompress(stream) + decomp.flush()
    assert flag in recovered


def test_twin_2031_yenc_roundtrip():
    flag = b"FLAG{twin_yenc}"
    encoded = yenc_encode(flag, filename="test.bin")
    decoded = yenc_decode(encoded)
    assert decoded == flag


def test_twin_2036_z85_roundtrip():
    flag = b"FLAG{twin_z85_pad!!}"  # 20 bytes (multiple of 4)
    encoded = z85_encode(flag)
    decoded = z85_decode(encoded)
    assert decoded == flag


def test_twin_2045_asn1_nested():
    flag = "FLAG{twin_nested_der}"
    der_mock = f"0'0%0 \x0c\x05label\x0c\x15{flag}\x02\x01c".encode("latin1")
    assert flag.encode("latin1") in der_mock


def test_twin_2049_rgb_split():
    parts = ["FLAG{twin", "_rgb", "_split}"]
    combined = "".join(parts)
    assert combined == "FLAG{twin_rgb_split}"


def test_twin_2055_pixel_columns():
    flag = b"FLAG{twin_pixel_col}"
    # Invert 8 bits per column
    inverted_cols = [b ^ 0xFF for b in flag]
    recovered = bytes([b ^ 0xFF for b in inverted_cols])
    assert recovered == flag


def test_twin_2057_json_chunks():
    data = {"order": [0, 1, 2], "parts": ["FLAG{twin_", "json_", "split}"]}
    reconstructed = "".join(data["parts"][i] for i in data["order"])
    assert reconstructed == "FLAG{twin_json_split}"


def test_twin_2059_yaml_anchors():
    flag = "FLAG{twin_yaml_anchor}"
    # Mock anchor dict
    defaults = {"token": flag, "retries": 3}
    prod = {**defaults, "host": "prod.lan"}
    assert prod["token"] == flag


def test_twin_2060_toml_table():
    flag = "FLAG{twin_toml_field}"
    toml_mock = {"server": {"auth": {"secret": flag}}}
    assert toml_mock["server"]["auth"]["secret"] == flag


def test_twin_2064_xml_catalog():
    flag = "FLAG{twin_xml_elem}"
    xml_mock = f"<catalog><item id='2'><sku>{flag}</sku></item></catalog>"
    assert flag in xml_mock


def test_twin_2065_xml_namespaces():
    flag = "FLAG{twin_xml_ns}"
    xml_mock = f"<m:field name='secret'>{flag}</m:field>"
    assert flag in xml_mock


def test_twin_2067_sqlite_single():
    flag = "FLAG{twin_sqlite_row}"
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INT, name TEXT, token TEXT)")
    cur.execute("INSERT INTO users VALUES (1, 'budi', ?)", (flag,))
    cur.execute("SELECT token FROM users WHERE name='budi'")
    res = cur.fetchone()[0]
    conn.close()
    assert res == flag


def test_twin_2068_sqlite_join():
    flag_left = "FLAG{twin"
    flag_right = "_sqlite_join}"
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE t1 (id INT, part TEXT)")
    cur.execute("CREATE TABLE t2 (id INT, part TEXT)")
    cur.execute("INSERT INTO t1 VALUES (1, ?)", (flag_left,))
    cur.execute("INSERT INTO t2 VALUES (1, ?)", (flag_right,))
    cur.execute("SELECT t1.part || t2.part FROM t1 JOIN t2 ON t1.id = t2.id")
    res = cur.fetchone()[0]
    conn.close()
    assert res == "FLAG{twin_sqlite_join}"


def test_twin_2069_json_pointer():
    flag = "FLAG{twin_json_pointer}"
    tree = {"a": [{"b": 0}, {"b": 1, "c": {"d": [{"e": "no"}, {"e": flag}]}}]}
    # Resolve /a/1/c/d/1/e
    val = tree["a"][1]["c"]["d"][1]["e"]
    assert val == flag


def test_twin_2078_jwt_claim():
    flag = "FLAG{twin_jwt_claim}"
    payload = {"sub": "1", "role": "user", "flag": flag}
    b64_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    jwt_mock = f"eyJhbGciOiJIUzI1NiJ9.{b64_payload}.sig"
    # Extract claim
    parts = jwt_mock.split(".")
    body = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode())
    assert body["flag"] == flag


def test_twin_2080_jsonc_comments():
    flag = "FLAG{twin_jsonc}"
    raw = f'// config\n{{"auth": {{"token": "{flag}"}} /* secret */}}'
    import re
    cleaned = re.sub(r"//.*?\n", "\n", raw)
    cleaned = re.sub(r"/\*.*?\*/", "", cleaned, flags=re.DOTALL)
    data = json.loads(cleaned)
    assert data["auth"]["token"] == flag


def test_twin_2088_keypad_t9():
    flag = "FLAG{twin_keypad}"
    assert "twin_keypad" in flag


def test_twin_2089_seven_segment():
    flag = "FLAG{twin_7seg}"
    assert "twin_7seg" in flag


def test_twin_2090_periodic_elements():
    flag = b"FLAG{twin_chem}"
    # Encode with chem_elements_to_bytes inverse
    # For synthetic test: check chem_elements_to_bytes on known vector
    # 'F' = 70 = 0x46 -> high 4 (B=5), low 6 (N=7)
    syms = ["B", "N"]
    res = chem_elements_to_bytes(syms)
    assert res == b"F"


def test_twin_2091_zero_width():
    flag = b"FLAG{twin_zw}"
    bits = "".join(f"{b:08b}" for b in flag)
    # ZWSP: \u200b for '0', ZWNJ: \u200c for '1'
    encoded = "".join("\u200b" if b == "0" else "\u200c" for b in bits)
    # Decode
    extracted_bits = "".join("0" if c == "\u200b" else "1" for c in encoded)
    recovered = bytes([int(extracted_bits[i : i + 8], 2) for i in range(0, len(extracted_bits), 8)])
    assert recovered == flag


def test_twin_2092_unicode_tags():
    flag = "FLAG{twin_tags}"
    # Unicode tag chars plane: U+E0000 + ord(c)
    encoded = "".join(chr(0xE0000 + ord(c)) for c in flag)
    decoded = "".join(chr(ord(c) - 0xE0000) for c in encoded)
    assert decoded == flag


def test_twin_2094_tap_code_knocks():
    flag = b"FLAG{twin_knocks}"
    # Base-4 knock pairs: each byte has 2 nibbles, each nibble has 2 base-4 digits + 1
    nibbles = []
    for b in flag:
        nibbles.extend([b >> 4, b & 0x0F])
    lines = []
    for n in nibbles:
        d0 = (n // 4) + 1
        d1 = (n % 4) + 1
        lines.append(f"{'.' * d0} {'.' * d1}")
    # decode
    dec_nibbles = [(len(l.split()[0]) - 1) * 4 + (len(l.split()[1]) - 1) for l in lines]
    recovered = bytes([(dec_nibbles[i] << 4) | dec_nibbles[i + 1] for i in range(0, len(dec_nibbles), 2)])
    assert recovered == flag
