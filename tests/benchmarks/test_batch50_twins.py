from __future__ import annotations

import base64
import io
import json
import re
import sqlite3
import zipfile
import zlib

from ctf_toolkit.forensics.zip_recover import extract_zip_extra_fields
from ctf_toolkit.utils.math import cellular_automaton_xor, solve_gf2_system
from ctf_toolkit.utils.text import normalize_homoglyphs


def test_twin_2177_sharded_zip_names():
    parts = ["00_FLA", "01_G{tw", "02_in_z", "03_ipn_", "04_69!}"]
    names = [f"{p}.part" for p in parts]
    extracted = "".join(re.match(r"\d+_([^.]+)\.part", n).group(1) for n in sorted(names))
    assert extracted == "FLAG{twin_zipn_69!}"


def test_twin_2178_polyglot_config_json():
    raw_cfg = {
        "service": "exporter",
        "nodes": [{"id": 0, "label": "test"}],
        "meta": {"owner": "alice", "release_token": "FLAG{twin_poly_config}"},
    }
    assert raw_cfg["meta"]["release_token"] == "FLAG{twin_poly_config}"


def test_twin_2179_jsonl_admin_event():
    events = [
        json.dumps({"user": "bob", "role": "user"}),
        json.dumps({"user": "root", "role": "admin", "token": "FLAG{twin_jsonl_71}"}),
    ]
    token = None
    for line in events:
        d = json.loads(line)
        if d.get("role") == "admin":
            token = d["token"]
    assert token == "FLAG{twin_jsonl_71}"


def test_twin_2180_jsonl_log_scan():
    events = [
        json.dumps({"event": "login", "payload": "none"}),
        json.dumps({"event": "export", "token": "FLAG{twin_jsonl_72}"}),
    ]
    m = re.search(r"FLAG\{twin_[^}]+\}", "\n".join(events))
    assert m and m.group(0) == "FLAG{twin_jsonl_72}"


def test_twin_2181_jsonl_event_filter():
    events = [
        json.dumps({"role": "guest"}),
        json.dumps({"role": "admin", "secret": "FLAG{twin_jsonl_73}"}),
    ]
    flag = next(json.loads(line)["secret"] for line in events if json.loads(line).get("role") == "admin")
    assert flag == "FLAG{twin_jsonl_73}"


def test_twin_2182_sqlite_account_query():
    conn = sqlite3.connect(":memory:")
    c = conn.cursor()
    c.execute("CREATE TABLE accounts(id INTEGER, name TEXT, role TEXT, enabled INTEGER, token TEXT)")
    c.execute("INSERT INTO accounts VALUES (1, 'alice', 'user', 1, 'none')")
    c.execute("INSERT INTO accounts VALUES (2, 'root', 'admin', 1, 'FLAG{twin_sql_74}')")
    c.execute("SELECT token FROM accounts WHERE role='admin' AND enabled=1")
    row = c.fetchone()
    assert row[0] == "FLAG{twin_sql_74}"
    conn.close()


def test_twin_2183_sqlite_root_token():
    conn = sqlite3.connect(":memory:")
    c = conn.cursor()
    c.execute("CREATE TABLE accounts(id INTEGER, name TEXT, role TEXT, enabled INTEGER, token TEXT)")
    c.execute("INSERT INTO accounts VALUES (10, 'operator', 'root', 1, 'FLAG{twin_sql_75}')")
    c.execute("SELECT token FROM accounts WHERE role='root' AND enabled=1")
    row = c.fetchone()
    assert row[0] == "FLAG{twin_sql_75}"
    conn.close()


def test_twin_2184_diff_patch_added_lines():
    diff = """--- a/config.cfg\n+++ b/config.cfg\n@@ -1,3 +1,4 @@\n line 1\n+FLAG{twin_diff_patch}\n line 2\n"""
    added = [line[1:] for line in diff.splitlines() if line.startswith("+") and not line.startswith("+++")]
    assert "FLAG{twin_diff_patch}" in added


def test_twin_2185_redacted_script_payload():
    payload = [ord(c) for c in "FLAG{twin_calc_77}"]
    assert bytes(payload).decode() == "FLAG{twin_calc_77}"


def test_twin_2186_python_byte_array():
    payload = [ord(c) for c in "FLAG{twin_calc_78}"]
    assert bytes(payload).decode() == "FLAG{twin_calc_78}"


def test_twin_2187_python_render_chars():
    payload = [ord(c) for c in "FLAG{twin_calc_79}"]
    assert bytes(payload).decode() == "FLAG{twin_calc_79}"


def test_twin_2188_js_fromcharcode():
    js_code = "var token = String.fromCharCode(70,76,65,71,123,116,119,105,110,95,106,115,95,56,48,125);"
    m = re.search(r"String\.fromCharCode\((.*?)\)", js_code)
    nums = [int(x.strip()) for x in m.group(1).split(",")]
    assert bytes(nums).decode() == "FLAG{twin_js_80}"


def test_twin_2189_js_token_eval():
    js_code = "var token = String.fromCharCode(70,76,65,71,123,116,119,105,110,95,106,115,95,56,49,125);"
    m = re.search(r"String\.fromCharCode\((.*?)\)", js_code)
    nums = [int(x.strip()) for x in m.group(1).split(",")]
    assert bytes(nums).decode() == "FLAG{twin_js_81}"


def test_twin_2190_homoglyph_normalization():
    # Cyrillic lookalikes: Е, Т, А, с, о
    cyrillic_flag = "FLАG{twin_hоmо}"
    normalized = normalize_homoglyphs(cyrillic_flag)
    assert normalized == "FLAG{twin_homo}"


def test_twin_2191_crontab_base64_cmd():
    crontab = "0 0 * * * echo RkxBR3t0d2luX2Nyb25fODN9 | base64 -d > /opt/secrets/token"
    m = re.search(r"echo\s+([A-Za-z0-9+/=]+)\s+\|\s+base64\s+-d", crontab)
    assert base64.b64decode(m.group(1)).decode() == "FLAG{twin_cron_83}"


def test_twin_2192_cellular_automaton_xor():
    target = b"FLAG{twin_ca84}"
    # Inverse of 1 step: curr[0] = target[0], curr[i] = target[i] ^ curr[i-1]
    target_bits = "".join(f"{b:08b}" for b in target)
    inv = [int(target_bits[0])]
    for b in target_bits[1:]:
        inv.append(int(b) ^ inv[-1])
    # 1 forward step recovers target
    recovered = cellular_automaton_xor(inv, 1)
    assert recovered == target


def test_twin_2193_cellular_automaton_multi_step():
    target = b"FLAG{twin_ca85}"
    target_bits = "".join(f"{b:08b}" for b in target)
    curr = [int(c) for c in target_bits]
    # invert 3 steps
    for _ in range(3):
        nxt = [curr[0]]
        for b in curr[1:]:
            nxt.append(b ^ nxt[-1])
        curr = nxt
    recovered = cellular_automaton_xor(curr, 3)
    assert recovered == target


def test_twin_2194_gf2_linear_solver():
    # Solve 16-bit toy system A * x = b over GF(2)
    # A = identity matrix
    n = 16
    A_rows = ["".join("1" if i == j else "0" for j in range(n)) for i in range(n)]
    b_vec = "0100000101000010"  # 'A', 'B'
    recovered = solve_gf2_system(A_rows, b_vec)
    assert recovered == b"AB"


def test_twin_2195_gf2_linear_matrix():
    # Solve 24-bit system with lower-triangular matrix
    target = b"CTF"
    bits = "".join(f"{b:08b}" for b in target)
    n = len(bits)
    # Lower triangular with 1s on diag and some subdiag
    A_rows = []
    for i in range(n):
        row = ["1" if j <= i and (i - j) % 2 == 0 else "0" for j in range(n)]
        A_rows.append("".join(row))
    # compute b = A * target
    b_list = []
    for i in range(n):
        val = sum(int(A_rows[i][j]) * int(bits[j]) for j in range(n)) % 2
        b_list.append(str(val))
    b_vec = "".join(b_list)
    recovered = solve_gf2_system(A_rows, b_vec)
    assert recovered == target


def test_twin_2196_acrostic_memo():
    lines = [
        "First line",
        "Last chance",
        "Always check",
        "Good luck",
    ]
    acrostic = "".join(line[0] for line in lines)
    assert acrostic == "FLAG"


def test_twin_2197_zip_extra_fields():
    buf = io.BytesIO()
    payload = b"FLAG{twin_extra89}"
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("item.bin")
        info.extra = b"XX" + len(payload).to_bytes(2, "little") + payload
        zf.writestr(info, b"content")
    fields = extract_zip_extra_fields(buf.getvalue())
    assert len(fields) == 1
    assert b"FLAG{twin_extra89}" in fields[0][1]


def test_twin_2198_zip_extra_metadata():
    buf = io.BytesIO()
    payload = b"FLAG{twin_extra90}"
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("secret.bin")
        info.extra = b"YY" + len(payload).to_bytes(2, "little") + payload
        zf.writestr(info, b"")
    fields = extract_zip_extra_fields(buf.getvalue())
    assert b"FLAG{twin_extra90}" in fields[0][1]


def test_twin_2199_git_loose_object():
    content = b"blob 20\x00FLAG{twin_git_obj91}"
    compressed = zlib.compress(content)
    decomp = zlib.decompress(compressed)
    assert b"FLAG{twin_git_obj91}" in decomp


def test_twin_2200_ca_rule_xor():
    target = b"FLAG{twin_ca92}"
    target_bits = "".join(f"{b:08b}" for b in target)
    curr = [int(c) for c in target_bits]
    for _ in range(5):
        nxt = [curr[0]]
        for b in curr[1:]:
            nxt.append(b ^ nxt[-1])
        curr = nxt
    recovered = cellular_automaton_xor(curr, 5)
    assert recovered == target


def test_twin_2201_gf2_linear_identity():
    target = b"FLAG{twin_sat93}"
    bits = "".join(f"{b:08b}" for b in target)
    n = len(bits)
    A_rows = ["".join("1" if i == j else "0" for j in range(n)) for i in range(n)]
    recovered = solve_gf2_system(A_rows, bits)
    assert recovered == target
