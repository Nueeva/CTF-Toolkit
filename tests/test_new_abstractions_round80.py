from __future__ import annotations

import io
import sqlite3
import zipfile

from ctf_toolkit.blockchain.calldata import decode_revert_reason
from ctf_toolkit.crypto.classical import xor_bytes
from ctf_toolkit.forensics.artifact_discovery import extract_strings_from_object
from ctf_toolkit.forensics.office import extract_docx_metadata
from ctf_toolkit.osint_misc.config_hunter import extract_cron_secrets, extract_sqlite_secrets
from ctf_toolkit.osint_misc.parsers import (
    ct_parser,
    whois_parser,
    html_comment_parser,
    json_secrets,
    landmark_matcher,
)
from ctf_toolkit.web.helpers import REQUEST_TEMPLATES


def test_blockchain_decode_revert_reason():
    # 0x08c379a0 is selector for Error(string)
    # ABI encoded "Unauthorized caller"
    selector = "08c379a0"
    # offset 0x20, len 0x13, string
    payload = "0000000000000000000000000000000000000000000000000000000000000020" \
              "0000000000000000000000000000000000000000000000000000000000000013" \
              "556e617574686f72697a65642063616c6c657200000000000000000000000000"
    res = decode_revert_reason(f"0x{selector}{payload}")
    assert res.get("error_type") == "Error(string)"
    assert "Unauthorized caller" in str(res.get("reason", ""))


def test_crypto_classical_xor_bytes():
    data = b"Antigravity"
    key = 0x42
    enc = xor_bytes(data, key)
    dec = xor_bytes(enc, key)
    assert dec == data


def test_forensics_extract_strings_from_object():
    blob = b"\x1f\x8b\x08\x00FLAG{loose_git_object_extracted}\x00\xff\xee"
    strings = extract_strings_from_object(blob, min_len=4)
    assert any("FLAG{loose_git_object_extracted}" in s for s in strings)


def test_forensics_docx_metadata():
    core_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                   xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:creator>lead_investigator_42</dc:creator>
    <dc:title>Confidential Case Report</dc:title>
</cp:coreProperties>"""
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("docProps/core.xml", core_xml)
    bio.seek(0)

    meta = extract_docx_metadata(bio)
    assert meta.get("creator") == "lead_investigator_42"
    assert meta.get("author") == "lead_investigator_42"
    assert meta.get("title") == "Confidential Case Report"


def test_config_hunter_cron_secrets():
    cron_text = """
# m h  dom mon dow   command
0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
*/15 * * * * echo 'R0VUU0ZMQUd7Y3Jvbl9iNjRfdG9rZW59' | base64 -d | sh
0 0 * * * token=secret_auth_token_99 /usr/bin/sync.sh
"""
    secrets = extract_cron_secrets(cron_text)
    assert "R0VUU0ZMQUd7Y3Jvbl9iNjRfdG9rZW59" in secrets
    assert "secret_auth_token_99" in secrets


def test_config_hunter_sqlite_secrets(tmp_path=None):
    import tempfile
    import os

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    tmp.close()
    conn = sqlite3.connect(tmp.name)
    c = conn.cursor()
    c.execute("CREATE TABLE users (id INT, username TEXT, secret_key TEXT);")
    c.execute("INSERT INTO users VALUES (1, 'admin', 'FLAG{sqlite_root_key_999}');")
    conn.commit()
    conn.close()

    found = extract_sqlite_secrets(tmp.name)
    os.remove(tmp.name)
    assert any("FLAG{sqlite_root_key_999}" in item for item in found)


def test_osint_parsers():
    # ct_parser
    entries = [{"name_value": "FLAG{ct_subdomain_found}.corp.internal"}]
    parsed_ct = ct_parser(entries)
    assert any("FLAG{ct_subdomain_found}" in p for p in parsed_ct)

    # whois_parser
    whois_raw = """
    aut-num:   AS64512
    org-name:  PT Cyber Defense Security
    country:   ID
    """
    whois_dict = whois_parser(whois_raw)
    assert whois_dict.get("org") == "PT Cyber Defense Security"
    assert whois_dict.get("country") == "ID"

    # html_comment_parser
    html = "<div><!-- secret_token: admin_secret_key_88 --></div>"
    comments = html_comment_parser(html)
    assert any("admin_secret_key_88" in c for c in comments)

    # json_secrets
    js = {"auth": {"token": "FLAG{nested_json_secret}"}}
    jsecrets = json_secrets(js)
    assert any("FLAG{nested_json_secret}" in s for s in jsecrets)

    # landmark_matcher
    assert landmark_matcher("Clue: 'Monas' di pusat kota") == "monas"
    assert landmark_matcher((-6.2088, 106.8456)) == "jakarta"


def test_web_helpers_sqli_template():
    assert "sqli" in REQUEST_TEMPLATES
    tmpl = REQUEST_TEMPLATES["sqli"]
    assert any("union select" in x.lower() for x in tmpl)
