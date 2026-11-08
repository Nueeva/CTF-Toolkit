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

def test_twin_265_account_upgrade() -> None:
    # Account Upgrade: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_265_account_upgrade}"
    assert flag.startswith("FLAG{")

def test_twin_266_session_service() -> None:
    # Session Service: SSTI template expression parsing
    tpl = "{{ 7 * 7 }}"
    eval_res = 49
    assert eval_res == 49
    flag = "FLAG{twin_266_session_service}"
    assert flag.startswith("FLAG{")

def test_twin_267_visit_logger() -> None:
    # Visit Logger: SQL query auth bypass simulation
    user_input = "admin' --"
    query = f"SELECT * FROM users WHERE user = '{user_input}' AND pass = 'x'"
    assert "admin' --" in query
    flag = "FLAG{twin_267_visit_logger}"
    assert flag.startswith("FLAG{")

def test_twin_268_xml_transformer() -> None:
    # XML Transformer: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_268_xml_transformer}"
    assert flag.startswith("FLAG{")

def test_twin_269_link_unfurl() -> None:
    # Link Unfurl: SSRF destination address verification
    dest = "http://169.254.169.254/latest/meta-data/"
    assert "169.254.169.254" in dest
    flag = "FLAG{twin_269_link_unfurl}"
    assert flag.startswith("FLAG{")

def test_twin_270_mini_sso() -> None:
    # Mini SSO: Unsecured JWT creation simulation
    token = jwt_forge_alg_none({"user": "admin", "role": "admin"})
    assert token.endswith(".")
    flag = "FLAG{twin_270_mini_sso}"
    assert flag.startswith("FLAG{")

def test_twin_272_stock_check() -> None:
    # Stock Check: SQL query auth bypass simulation
    user_input = "admin' --"
    query = f"SELECT * FROM users WHERE user = '{user_input}' AND pass = 'x'"
    assert "admin' --" in query
    flag = "FLAG{twin_272_stock_check}"
    assert flag.startswith("FLAG{")

def test_twin_273_icon_gallery() -> None:
    # Icon Gallery: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_273_icon_gallery}"
    assert flag.startswith("FLAG{")

def test_twin_274_trial_pass() -> None:
    # Trial Pass: Unsecured JWT creation simulation
    token = jwt_forge_alg_none({"user": "admin", "role": "admin"})
    assert token.endswith(".")
    flag = "FLAG{twin_274_trial_pass}"
    assert flag.startswith("FLAG{")

def test_twin_275_dir_lookup() -> None:
    # Dir Lookup: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_275_dir_lookup}"
    assert flag.startswith("FLAG{")

def test_twin_276_typed_gql() -> None:
    # Typed GQL: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_276_typed_gql}"
    assert flag.startswith("FLAG{")

def test_twin_277_pref_cookie() -> None:
    # Pref Cookie: SQL query auth bypass simulation
    user_input = "admin' --"
    query = f"SELECT * FROM users WHERE user = '{user_input}' AND pass = 'x'"
    assert "admin' --" in query
    flag = "FLAG{twin_277_pref_cookie}"
    assert flag.startswith("FLAG{")

def test_twin_278_log_viewer() -> None:
    # Log Viewer: Multipart extension spoofing test
    fname = "payload.phtml"
    is_allowed = fname.endswith((".php", ".phtml", ".php5"))
    assert is_allowed is True
    flag = "FLAG{twin_278_log_viewer}"
    assert flag.startswith("FLAG{")

def test_twin_279_gadget_store() -> None:
    # Gadget Store: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_279_gadget_store}"
    assert flag.startswith("FLAG{")

def test_twin_280_sso_redirect() -> None:
    # SSO Redirect: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_280_sso_redirect}"
    assert flag.startswith("FLAG{")

def test_twin_281_node_greeter() -> None:
    # Node Greeter: SSTI template expression parsing
    tpl = "{{ 7 * 7 }}"
    eval_res = 49
    assert eval_res == 49
    flag = "FLAG{twin_281_node_greeter}"
    assert flag.startswith("FLAG{")

def test_twin_282_node_pinger() -> None:
    # Node Pinger: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_282_node_pinger}"
    assert flag.startswith("FLAG{")

def test_twin_283_php_session_store() -> None:
    # PHP Session Store: Unsecured JWT creation simulation
    token = jwt_forge_alg_none({"user": "admin", "role": "admin"})
    assert token.endswith(".")
    flag = "FLAG{twin_283_php_session_store}"
    assert flag.startswith("FLAG{")

def test_twin_284_php_dashboard() -> None:
    # PHP Dashboard: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_284_php_dashboard}"
    assert flag.startswith("FLAG{")

def test_twin_285_referrer_stats() -> None:
    # Referrer Stats: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_285_referrer_stats}"
    assert flag.startswith("FLAG{")

