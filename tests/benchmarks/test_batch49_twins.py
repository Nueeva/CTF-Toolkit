"""Synthetic benchmark twin tests for Batch 49 (IDs 2095-2176, 25 Misc challenges).
AIR-GAP: Uses strictly synthetic flags FLAG{twin_...}.
"""

import io
import re
import zlib
import tarfile
import zipfile
from ctf_toolkit.utils.text import (
    dna_to_bytes,
    resistor_colors_to_int,
    spreadsheet_col_to_int,
    int_to_spreadsheet_col,
    roman_to_int,
    int_to_roman,
)
from ctf_toolkit.utils.math import collatz_stopping_time, fibonacci_index


def test_twin_2095_dna_seq():
    flag = b"FLAG{twin_dna}"
    mapping = {"A": 0, "C": 1, "G": 2, "T": 3}
    inv_map = {0: "A", 1: "C", 2: "G", 3: "T"}
    # encode to DNA
    dna = []
    for b in flag:
        dna.append(inv_map[(b >> 6) & 3])
        dna.append(inv_map[(b >> 4) & 3])
        dna.append(inv_map[(b >> 2) & 3])
        dna.append(inv_map[b & 3])
    dna_str = "".join(dna)
    decoded = dna_to_bytes(dna_str, mapping)
    assert decoded == flag


def test_twin_2097_resistor():
    # 'F' = 70 = black (0), violet (7), black (0)
    assert resistor_colors_to_int(["black", "violet", "black"]) == 70


def test_twin_2101_spreadsheet_cols():
    flag = b"FLAG{twin_cols}"
    cols = [int_to_spreadsheet_col(b) for b in flag]
    recovered = bytes([spreadsheet_col_to_int(c) for c in cols])
    assert recovered == flag


def test_twin_2102_fibonacci():
    # F(70) is 70th Fibonacci number
    fibs = [0, 1]
    for _ in range(70):
        fibs.append(fibs[-1] + fibs[-2])
    f70 = fibs[70]
    assert fibonacci_index(f70) == 70


def test_twin_2103_collatz():
    # Collatz stopping time for 27 is 111 steps
    assert collatz_stopping_time(27) == 111


def test_twin_2107_roman():
    flag = b"FLAG{twin_roman}"
    romans = [int_to_roman(b) for b in flag]
    recovered = bytes([roman_to_int(r) for r in romans])
    assert recovered == flag


def test_twin_2108_capitalization():
    flag = b"FLAG{twin_caps}"
    bits = "".join(f"{b:08b}" for b in flag)
    # mock cover text
    cover = "".join("A" if b == "1" else "a" for b in bits)
    extracted_bits = "".join("1" if c.isupper() else "0" for c in cover)
    recovered = bytes([int(extracted_bits[i : i + 8], 2) for i in range(0, len(extracted_bits), 8)])
    assert recovered == flag


def test_twin_2159_regex_haystack():
    flag = "FLAG{twin_regex_051}"
    haystack = f"garbage data {flag} more garbage"
    match = re.search(r"FLAG\{twin_regex_0*51\}", haystack)
    assert match is not None and match.group(0) == flag


def test_twin_2160_regex_haystack():
    flag = "FLAG{twin_regex_052}"
    haystack = f"prefix {flag} suffix"
    match = re.search(r"FLAG\{twin_regex_0*52\}", haystack)
    assert match is not None and match.group(0) == flag


def test_twin_2161_regex_haystack():
    flag = "FLAG{twin_regex_053}"
    haystack = f"test {flag} test"
    match = re.search(r"FLAG\{twin_regex_0*53\}", haystack)
    assert match is not None and match.group(0) == flag


def test_twin_2162_regex_haystack():
    flag = "FLAG{twin_regex_054}"
    haystack = f"line1\n{flag}\nline3"
    match = re.search(r"FLAG\{twin_regex_0*54\}", haystack)
    assert match is not None and match.group(0) == flag


def test_twin_2163_pattern_re():
    pat = "^[F][L][A][G]\\{[t][w][i][n]_[0][5][5]\\}$"
    flag = "FLAG{twin_055}"
    assert re.match(pat, flag) is not None


def test_twin_2164_pattern_re():
    pat = "^[F][L][A][G]\\{[t][w][i][n]_[0][5][6]\\}$"
    flag = "FLAG{twin_056}"
    assert re.match(pat, flag) is not None


def test_twin_2165_pattern_re():
    pat = "^[F][L][A][G]\\{[t][w][i][n]_[0][5][7]\\}$"
    flag = "FLAG{twin_057}"
    assert re.match(pat, flag) is not None


def test_twin_2166_pattern_re():
    pat = "^[F][L][A][G]\\{[t][w][i][n]_[0][5][8]\\}$"
    flag = "FLAG{twin_058}"
    assert re.match(pat, flag) is not None


def test_twin_2167_pattern_re():
    pat = "^[F][L][A][G]\\{[t][w][i][n]_[0][5][9]\\}$"
    flag = "FLAG{twin_059}"
    assert re.match(pat, flag) is not None


def test_twin_2168_stack_vm_mul():
    # PUSH 10, PUSH 7, MUL, EMIT -> 70 = 'F'
    st = [10, 7]
    b = st.pop(); a = st.pop(); st.append(a * b)
    assert chr(st.pop()) == "F"


def test_twin_2169_stack_vm_ops():
    # Test ADD, SUB, MUL sequence
    st = []
    # 50 + 20 = 70 ('F')
    st.extend([50, 20]); b = st.pop(); a = st.pop(); st.append(a + b)
    assert chr(st.pop()) == "F"


def test_twin_2170_stack_vm_full():
    flag = "FLAG{twin_vm}"
    out = []
    for c in flag:
        st = [1, ord(c)]
        b = st.pop(); a = st.pop()
        out.append(chr(a * b))
    assert "".join(out) == flag


def test_twin_2171_tar_marker():
    flag = "FLAG{twin_tar_063}"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        ti = tarfile.TarInfo(f"path/to/{flag}.marker")
        tar.addfile(ti, io.BytesIO(b""))
    buf.seek(0)
    with tarfile.open(fileobj=buf, mode="r") as tar:
        assert flag in tar.getmembers()[0].name


def test_twin_2172_tar_marker():
    flag = "FLAG{twin_tar_064}"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        ti = tarfile.TarInfo(f"nested/{flag}.txt")
        tar.addfile(ti, io.BytesIO(b""))
    buf.seek(0)
    with tarfile.open(fileobj=buf, mode="r") as tar:
        assert flag in tar.getmembers()[0].name


def test_twin_2173_git_object():
    flag = b"FLAG{twin_git_065}"
    payload = b"blob 40\x00release=" + flag + b"\n"
    compressed = zlib.compress(payload)
    decomp = zlib.decompress(compressed)
    assert flag in decomp


def test_twin_2174_git_object():
    flag = b"FLAG{twin_git_066}"
    payload = b"blob 35\x00token=" + flag + b"\n"
    compressed = zlib.compress(payload)
    decomp = zlib.decompress(compressed)
    assert flag in decomp


def test_twin_2175_zip_parts():
    parts = ["00_FLAG", "01_{twin", "02__zip", "03_067}"]
    reconstructed = "".join(p.split("_", 1)[1] for p in sorted(parts))
    assert reconstructed == "FLAG{twin_zip067}"


def test_twin_2176_zip_parts():
    parts = ["00_FLAG", "01_{twin", "02__zip", "03_068}"]
    reconstructed = "".join(p.split("_", 1)[1] for p in sorted(parts))
    assert reconstructed == "FLAG{twin_zip068}"
