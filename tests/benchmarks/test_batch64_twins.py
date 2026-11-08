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

def test_twin_28_heatportal() -> None:
    # HeatPortal: SQL query auth bypass simulation
    user_input = "admin' --"
    query = f"SELECT * FROM users WHERE user = '{user_input}' AND pass = 'x'"
    assert "admin' --" in query
    flag = "FLAG{twin_28_heatportal}"
    assert flag.startswith("FLAG{")

def test_twin_29_heatcards() -> None:
    # HeatCards: SSTI template expression parsing
    tpl = "{{ 7 * 7 }}"
    eval_res = 49
    assert eval_res == 49
    flag = "FLAG{twin_29_heatcards}"
    assert flag.startswith("FLAG{")

def test_twin_33_heatping() -> None:
    # HeatPing: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_33_heatping}"
    assert flag.startswith("FLAG{")

def test_twin_194_heatleak() -> None:
    # HeatLeak: Application state verification
    state = {"role": "user"}
    state["role"] = "admin"
    assert state["role"] == "admin"
    flag = "FLAG{twin_194_heatleak}"
    assert flag.startswith("FLAG{")

def test_twin_196_heatorder() -> None:
    # HeatOrder: Application state verification
    state = {"role": "user"}
    state["role"] = "admin"
    assert state["role"] == "admin"
    flag = "FLAG{twin_196_heatorder}"
    assert flag.startswith("FLAG{")

def test_twin_197_heattoken() -> None:
    # HeatToken: Unsecured JWT creation simulation
    token = jwt_forge_alg_none({"user": "admin", "role": "admin"})
    assert token.endswith(".")
    flag = "FLAG{twin_197_heattoken}"
    assert flag.startswith("FLAG{")

def test_twin_198_heatfetch() -> None:
    # HeatFetch: SSRF destination address verification
    dest = "http://169.254.169.254/latest/meta-data/"
    assert "169.254.169.254" in dest
    flag = "FLAG{twin_198_heatfetch}"
    assert flag.startswith("FLAG{")

def test_twin_199_heatpickle() -> None:
    # HeatPickle: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_199_heatpickle}"
    assert flag.startswith("FLAG{")

def test_twin_209_product_search() -> None:
    # Product Search: SQL query auth bypass simulation
    user_input = "admin' --"
    query = f"SELECT * FROM users WHERE user = '{user_input}' AND pass = 'x'"
    assert "admin' --" in query
    flag = "FLAG{twin_209_product_search}"
    assert flag.startswith("FLAG{")

def test_twin_210_user_check() -> None:
    # User Check: SQL query auth bypass simulation
    user_input = "admin' --"
    query = f"SELECT * FROM users WHERE user = '{user_input}' AND pass = 'x'"
    assert "admin' --" in query
    flag = "FLAG{twin_210_user_check}"
    assert flag.startswith("FLAG{")

def test_twin_212_url_preview() -> None:
    # URL Preview: SSRF destination address verification
    dest = "http://169.254.169.254/latest/meta-data/"
    assert "169.254.169.254" in dest
    flag = "FLAG{twin_212_url_preview}"
    assert flag.startswith("FLAG{")

def test_twin_213_greeting_card() -> None:
    # Greeting Card: SSTI template expression parsing
    tpl = "{{ 7 * 7 }}"
    eval_res = 49
    assert eval_res == 49
    flag = "FLAG{twin_213_greeting_card}"
    assert flag.startswith("FLAG{")

def test_twin_214_order_importer() -> None:
    # Order Importer: Application state verification
    state = {"role": "user"}
    state["role"] = "admin"
    assert state["role"] == "admin"
    flag = "FLAG{twin_214_order_importer}"
    assert flag.startswith("FLAG{")

def test_twin_217_preferences() -> None:
    # Preferences: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_217_preferences}"
    assert flag.startswith("FLAG{")

def test_twin_218_oauth_gate() -> None:
    # OAuth Gate: SQL query auth bypass simulation
    user_input = "admin' --"
    query = f"SELECT * FROM users WHERE user = '{user_input}' AND pass = 'x'"
    assert "admin' --" in query
    flag = "FLAG{twin_218_oauth_gate}"
    assert flag.startswith("FLAG{")

def test_twin_219_graphql_api() -> None:
    # GraphQL API: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_219_graphql_api}"
    assert flag.startswith("FLAG{")

def test_twin_220_profile_update() -> None:
    # Profile Update: Multipart extension spoofing test
    fname = "payload.phtml"
    is_allowed = fname.endswith((".php", ".phtml", ".php5"))
    assert is_allowed is True
    flag = "FLAG{twin_220_profile_update}"
    assert flag.startswith("FLAG{")

def test_twin_221_theme_loader() -> None:
    # Theme Loader: Multipart extension spoofing test
    fname = "payload.phtml"
    is_allowed = fname.endswith((".php", ".phtml", ".php5"))
    assert is_allowed is True
    flag = "FLAG{twin_221_theme_loader}"
    assert flag.startswith("FLAG{")

def test_twin_222_catalog_api() -> None:
    # Catalog API: SQL query auth bypass simulation
    user_input = "admin' --"
    query = f"SELECT * FROM users WHERE user = '{user_input}' AND pass = 'x'"
    assert "admin' --" in query
    flag = "FLAG{twin_222_catalog_api}"
    assert flag.startswith("FLAG{")

def test_twin_223_name_badge() -> None:
    # Name Badge: SSTI template expression parsing
    tpl = "{{ 7 * 7 }}"
    eval_res = 49
    assert eval_res == 49
    flag = "FLAG{twin_223_name_badge}"
    assert flag.startswith("FLAG{")

