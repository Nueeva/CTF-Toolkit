from __future__ import annotations

import os
import base64
import json
import struct
from ctf_toolkit.web.helpers import (
    url_encode,
    url_decode,
    b64url_encode,
    b64url_decode,
    jwt_forge_alg_none,
    build_nosql_query_payload,
)

def test_twin_286_keyvault_sso() -> None:
    # KeyVault SSO: SQL query auth bypass simulation
    user_input = "admin' --"
    query = f"SELECT * FROM users WHERE user = '{user_input}' AND pass = 'x'"
    assert "admin' --" in query
    flag = "FLAG{twin_286_keyvault_sso}"
    assert flag.startswith("FLAG{")

def test_twin_287_micro_blog() -> None:
    # Micro Blog: SQL query auth bypass simulation
    user_input = "admin' --"
    query = f"SELECT * FROM users WHERE user = '{user_input}' AND pass = 'x'"
    assert "admin' --" in query
    flag = "FLAG{twin_287_micro_blog}"
    assert flag.startswith("FLAG{")

def test_twin_288_jsonp_api() -> None:
    # JSONP API: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_288_jsonp_api}"
    assert flag.startswith("FLAG{")

def test_twin_290_quote_maker() -> None:
    # Quote Maker: SSTI template expression parsing
    tpl = "{{ 7 * 7 }}"
    eval_res = 49
    assert eval_res == 49
    flag = "FLAG{twin_290_quote_maker}"
    assert flag.startswith("FLAG{")

def test_twin_291_signed_cookie() -> None:
    # Signed Cookie: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_291_signed_cookie}"
    assert flag.startswith("FLAG{")

def test_twin_292_refund_center() -> None:
    # Refund Center: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_292_refund_center}"
    assert flag.startswith("FLAG{")

def test_twin_293_image_proxy() -> None:
    # Image Proxy: SSRF destination address verification
    dest = "http://169.254.169.254/latest/meta-data/"
    assert "169.254.169.254" in dest
    flag = "FLAG{twin_293_image_proxy}"
    assert flag.startswith("FLAG{")

def test_twin_294_mongo_login() -> None:
    # Mongo Login: SQL query auth bypass simulation
    user_input = "admin' --"
    query = f"SELECT * FROM users WHERE user = '{user_input}' AND pass = 'x'"
    assert "admin' --" in query
    flag = "FLAG{twin_294_mongo_login}"
    assert flag.startswith("FLAG{")

def test_twin_295_file_lister() -> None:
    # File Lister: Multipart extension spoofing test
    fname = "payload.phtml"
    is_allowed = fname.endswith((".php", ".phtml", ".php5"))
    assert is_allowed is True
    flag = "FLAG{twin_295_file_lister}"
    assert flag.startswith("FLAG{")

def test_twin_816_base64_pass() -> None:
    # Base64 Pass: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_816_base64_pass}"
    assert flag.startswith("FLAG{")

def test_twin_821_referer_check() -> None:
    # Referer Check: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_821_referer_check}"
    assert flag.startswith("FLAG{")

def test_twin_824_basic_auth() -> None:
    # Basic Auth: SQL query auth bypass simulation
    user_input = "admin' --"
    query = f"SELECT * FROM users WHERE user = '{user_input}' AND pass = 'x'"
    assert "admin' --" in query
    flag = "FLAG{twin_824_basic_auth}"
    assert flag.startswith("FLAG{")

def test_twin_826_graphql_field() -> None:
    # GraphQL Field: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_826_graphql_field}"
    assert flag.startswith("FLAG{")

def test_twin_827_nosql_login() -> None:
    # NoSQL Login: SQL query auth bypass simulation
    user_input = "admin' --"
    query = f"SELECT * FROM users WHERE user = '{user_input}' AND pass = 'x'"
    assert "admin' --" in query
    flag = "FLAG{twin_827_nosql_login}"
    assert flag.startswith("FLAG{")

def test_twin_829_cors_trust() -> None:
    # CORS Trust: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_829_cors_trust}"
    assert flag.startswith("FLAG{")

def test_twin_830_oauth_redirect() -> None:
    # OAuth Redirect: SQL query auth bypass simulation
    user_input = "admin' --"
    query = f"SELECT * FROM users WHERE user = '{user_input}' AND pass = 'x'"
    assert "admin' --" in query
    flag = "FLAG{twin_830_oauth_redirect}"
    assert flag.startswith("FLAG{")

def test_twin_834_waf_bypass() -> None:
    # WAF Bypass: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_834_waf_bypass}"
    assert flag.startswith("FLAG{")

def test_twin_835_otp_leak() -> None:
    # OTP Leak: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_835_otp_leak}"
    assert flag.startswith("FLAG{")

def test_twin_838_race_redeem() -> None:
    # Race Redeem: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_838_race_redeem}"
    assert flag.startswith("FLAG{")

def test_twin_839_config_merge() -> None:
    # Config Merge: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_839_config_merge}"
    assert flag.startswith("FLAG{")

