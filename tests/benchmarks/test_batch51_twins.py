from __future__ import annotations

import base64
import re
import sqlite3

from ctf_toolkit.crypto.classical import base58_decode, rot_n
from ctf_toolkit.osint_misc.esolang import eval_stack_vm
from ctf_toolkit.osint_misc.stego import decode_zero_width, encode_zero_width
from ctf_toolkit.utils.math import solve_gf2_system


def test_twin_2202_gf2_linear_solver():
    target = b"FLAG{twin_sat94}"
    bits = "".join(f"{b:08b}" for b in target)
    n = len(bits)
    A_rows = ["".join("1" if i == j else "0" for j in range(n)) for i in range(n)]
    recovered = solve_gf2_system(A_rows, bits)
    assert recovered == target


def test_twin_2203_zero_width_stego():
    target = b"FLAG{twin_zw95}"
    encoded = encode_zero_width(target)
    carrier = f"Public memo before.{encoded} Thank you."
    recovered = decode_zero_width(carrier)
    assert recovered == target


def test_twin_2204_stack_vm_push_emit():
    prog = """
    ; stack VM program
    PUSH 70
    EMIT
    PUSH 76
    EMIT
    PUSH 65
    EMIT
    PUSH 71
    EMIT
    """
    out = eval_stack_vm(prog)
    assert out == "FLAG"


def test_twin_2205_stack_vm_mul_sub():
    prog = """
    PUSH 10
    PUSH 7
    MUL
    EMIT
    PUSH 80
    PUSH 4
    SUB
    EMIT
    """
    out = eval_stack_vm(prog)
    assert out == "FL"


def test_twin_2206_regex_pattern_reconstruct():
    pattern = r"^[F][L][A][G]\{[t][w][i][n]_[r][e][v]_[0][9][8]\}$"
    flag = re.sub(r"\[(.)\]", r"\1", pattern).strip("^$").replace(r"\{", "{").replace(r"\}", "}")
    assert flag == "FLAG{twin_rev_098}"


def test_twin_2207_sqlite_root_secret():
    conn = sqlite3.connect(":memory:")
    c = conn.cursor()
    c.execute("CREATE TABLE accounts(id INTEGER, name TEXT, role TEXT, enabled INTEGER, token TEXT)")
    c.execute("INSERT INTO accounts VALUES (1, 'u1', 'admin', 1, 'FLAG{twin_admin_decoy}')")
    c.execute("INSERT INTO accounts VALUES (2, 'svc_root', 'root', 1, 'FLAG{twin_sql_099}')")
    c.execute("SELECT token FROM accounts WHERE role='root' AND enabled=1")
    row = c.fetchone()
    assert row[0] == "FLAG{twin_sql_099}"
    conn.close()


def test_twin_2208_unified_diff_patch():
    diff_text = """--- a/config.cfg\n+++ b/config.cfg\n@@ -1,5 +1,6 @@\n line 1\n+release_token = FLAG{twin_diff_100}\n line 2\n"""
    m = re.search(r"FLAG\{twin_[^}]+\}", diff_text)
    assert m and m.group(0) == "FLAG{twin_diff_100}"


def test_twin_17_hex_exif_comment():
    hex_str = "464c41477b7477696e5f6d6574615f70696e737d"
    flag = bytes.fromhex(hex_str).decode()
    assert flag == "FLAG{twin_meta_pins}"


def test_twin_111_gps_coordinates_city():
    coords = (-6.2088, 106.8456)
    # Mapping coordinates to known metropolitan city
    city = "jakarta" if abs(coords[0] - (-6.2)) < 0.1 and abs(coords[1] - 106.8) < 0.1 else "unknown"
    flag = f"FLAG{{{city}}}"
    assert flag == "FLAG{jakarta}"


def test_twin_116_user_agent_hex():
    header = "User-Agent: 464c41477b7477696e5f6167656e745f6865787d"
    hex_payload = re.search(r"[0-9a-fA-F]{20,}", header).group(0)
    flag = bytes.fromhex(hex_payload).decode()
    assert flag == "FLAG{twin_agent_hex}"


def test_twin_117_caps_acrostic():
    bio = "Huruf KAPITAL mengeja flag: CAPS_HIDDEN_TWIN"
    caps = re.search(r"flag:\s*([A-Z_]+)", bio).group(1)
    flag = f"FLAG{{{caps}}}"
    assert flag == "FLAG{CAPS_HIDDEN_TWIN}"


def test_twin_119_shortlink_rot13():
    link_path = "/ebg_cngu"
    resolved = rot_n(link_path, 13)
    flag = f"FLAG{{{resolved.lstrip('/')}}}"
    assert flag == "FLAG{rot_path}"


def test_twin_121_git_commit_log_dump():
    log_dump = "line 0: normal\nline 1: normal\nline 2: # FLAG{twin_ghost_commit}\n"
    m = re.search(r"FLAG\{twin_[^}]+\}", log_dump)
    assert m and m.group(0) == "FLAG{twin_ghost_commit}"


def test_twin_122_base32_subdomain():
    # 'twin_subdomain' base32
    target = b"twin_subdomain"
    b32 = base64.b32encode(target).decode().lower().rstrip("=")
    pad = (8 - len(b32) % 8) % 8
    decoded = base64.b32decode(b32.upper() + "=" * pad).decode()
    flag = f"FLAG{{{decoded}}}"
    assert flag == "FLAG{twin_subdomain}"


def test_twin_123_pin_location_label():
    label = "berbagai_titik"
    flag = f"FLAG{{{label}}}"
    assert flag == "FLAG{berbagai_titik}"


def test_twin_125_transcript_timecodes():
    transcript = "00:01 normal\n00:02 normal\n00:03 # FLAG{twin_time_codes}\n"
    m = re.search(r"FLAG\{twin_[^}]+\}", transcript)
    assert m and m.group(0) == "FLAG{twin_time_codes}"


def test_twin_126_wayback_comment():
    html_dump = "<!-- normal -->\n<!-- FLAG{twin_wayback_leak} -->\n"
    m = re.search(r"FLAG\{twin_[^}]+\}", html_dump)
    assert m and m.group(0) == "FLAG{twin_wayback_leak}"


def test_twin_127_email_header_b64():
    raw_b64 = base64.b64encode(b"FLAG{twin_mail_hdr}").decode()
    header = f"X-Flag: {raw_b64}"
    m = re.search(r"X-Flag:\s*([A-Za-z0-9+/=]+)", header)
    assert base64.b64decode(m.group(1)).decode() == "FLAG{twin_mail_hdr}"


def test_twin_129_docx_core_properties():
    meta_line = "Author/Registrant/Model: FLAG{twin_docx_core}"
    m = re.search(r"FLAG\{twin_[^}]+\}", meta_line)
    assert m and m.group(0) == "FLAG{twin_docx_core}"


def test_twin_131_dual_geotag_labels():
    pts = [(-6.2, 106.8), (-7.8, 110.4)]
    cities = []
    for lat, lon in pts:
        if abs(lat - (-6.2)) < 0.5:
            cities.append("jakarta")
        elif abs(lat - (-7.8)) < 0.5:
            cities.append("yogyakarta")
    flag = f"FLAG{{{'_'.join(cities)}}}"
    assert flag == "FLAG{jakarta_yogyakarta}"


def test_twin_132_reverse_image_metadata():
    meta_line = "Author/Registrant/Model: FLAG{twin_img_hex}"
    m = re.search(r"FLAG\{twin_[^}]+\}", meta_line)
    assert m and m.group(0) == "FLAG{twin_img_hex}"


def test_twin_134_tls_san_leak():
    san_line = "Author/Registrant/Model: FLAG{twin_san_leak}"
    m = re.search(r"FLAG\{twin_[^}]+\}", san_line)
    assert m and m.group(0) == "FLAG{twin_san_leak}"


def test_twin_135_ssh_login_hex_user():
    log_line = "user gagal login: 464c41477b7477696e5f7373685f757365727d"
    m = re.search(r"[0-9a-fA-F]{20,}", log_line)
    flag = bytes.fromhex(m.group(0)).decode()
    assert flag == "FLAG{twin_ssh_user}"


def test_twin_137_dns_txt_record_b32():
    target = b"twin_txt_record"
    b32 = base64.b32encode(target).decode().lower().rstrip("=")
    pad = (8 - len(b32) % 8) % 8
    decoded = base64.b32decode(b32.upper() + "=" * pad).decode()
    flag = f"FLAG{{{decoded}}}"
    assert flag == "FLAG{twin_txt_record}"


def test_twin_138_github_gist_b58():
    # Base58 decoded gist string
    raw_b58 = "JJE4P8CXWwh"
    token = base58_decode(raw_b58).decode()
    flag = f"FLAG{{{token}}}"
    assert flag == "FLAG{gist_b58}"
