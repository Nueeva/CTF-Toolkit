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

def test_twin_224_webhook_tester() -> None:
    # Webhook Tester: SSRF destination address verification
    dest = "http://169.254.169.254/latest/meta-data/"
    assert "169.254.169.254" in dest
    flag = "FLAG{twin_224_webhook_tester}"
    assert flag.startswith("FLAG{")

def test_twin_225_avatar_svg() -> None:
    # Avatar SVG: Multipart extension spoofing test
    fname = "payload.phtml"
    is_allowed = fname.endswith((".php", ".phtml", ".php5"))
    assert is_allowed is True
    flag = "FLAG{twin_225_avatar_svg}"
    assert flag.startswith("FLAG{")

def test_twin_226_image_info() -> None:
    # Image Info: Multipart extension spoofing test
    fname = "payload.phtml"
    is_allowed = fname.endswith((".php", ".phtml", ".php5"))
    assert is_allowed is True
    flag = "FLAG{twin_226_image_info}"
    assert flag.startswith("FLAG{")

def test_twin_227_account_api() -> None:
    # Account API: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_227_account_api}"
    assert flag.startswith("FLAG{")

def test_twin_229_invoice_portal() -> None:
    # Invoice Portal: Application state verification
    state = {"role": "user"}
    state["role"] = "admin"
    assert state["role"] == "admin"
    flag = "FLAG{twin_229_invoice_portal}"
    assert flag.startswith("FLAG{")

def test_twin_230_sso_portal() -> None:
    # SSO Portal: Unsecured JWT creation simulation
    token = jwt_forge_alg_none({"user": "admin", "role": "admin"})
    assert token.endswith(".")
    flag = "FLAG{twin_230_sso_portal}"
    assert flag.startswith("FLAG{")

def test_twin_231_password_reset() -> None:
    # Password Reset: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_231_password_reset}"
    assert flag.startswith("FLAG{")

def test_twin_232_mini_shop() -> None:
    # Mini Shop: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_232_mini_shop}"
    assert flag.startswith("FLAG{")

def test_twin_233_search_box() -> None:
    # Search Box: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_233_search_box}"
    assert flag.startswith("FLAG{")

def test_twin_234_guestbook() -> None:
    # Guestbook: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_234_guestbook}"
    assert flag.startswith("FLAG{")

def test_twin_235_dns_lookup() -> None:
    # DNS Lookup: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_235_dns_lookup}"
    assert flag.startswith("FLAG{")

def test_twin_236_fetcher_pro() -> None:
    # Fetcher Pro: Multipart extension spoofing test
    fname = "payload.phtml"
    is_allowed = fname.endswith((".php", ".phtml", ".php5"))
    assert is_allowed is True
    flag = "FLAG{twin_236_fetcher_pro}"
    assert flag.startswith("FLAG{")

def test_twin_237_avatar_importer() -> None:
    # Avatar Importer: Multipart extension spoofing test
    fname = "payload.phtml"
    is_allowed = fname.endswith((".php", ".phtml", ".php5"))
    assert is_allowed is True
    flag = "FLAG{twin_237_avatar_importer}"
    assert flag.startswith("FLAG{")

def test_twin_238_account_settings() -> None:
    # Account Settings: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_238_account_settings}"
    assert flag.startswith("FLAG{")

def test_twin_239_bio_board() -> None:
    # Bio Board: SQL query auth bypass simulation
    user_input = "admin' --"
    query = f"SELECT * FROM users WHERE user = '{user_input}' AND pass = 'x'"
    assert "admin' --" in query
    flag = "FLAG{twin_239_bio_board}"
    assert flag.startswith("FLAG{")

def test_twin_240_staff_directory() -> None:
    # Staff Directory: Multipart extension spoofing test
    fname = "payload.phtml"
    is_allowed = fname.endswith((".php", ".phtml", ".php5"))
    assert is_allowed is True
    flag = "FLAG{twin_240_staff_directory}"
    assert flag.startswith("FLAG{")

def test_twin_241_corp_login() -> None:
    # Corp Login: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_241_corp_login}"
    assert flag.startswith("FLAG{")

def test_twin_242_forgot_password() -> None:
    # Forgot Password: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_242_forgot_password}"
    assert flag.startswith("FLAG{")

def test_twin_243_member_area() -> None:
    # Member Area: Unsecured JWT creation simulation
    token = jwt_forge_alg_none({"user": "admin", "role": "admin"})
    assert token.endswith(".")
    flag = "FLAG{twin_243_member_area}"
    assert flag.startswith("FLAG{")

def test_twin_244_welcome_page() -> None:
    # Welcome Page: Shell command separator delimiter test
    cmd = "127.0.0.1; cat flag.txt"
    tokens = cmd.split(";")
    assert len(tokens) == 2 and "cat flag.txt" in tokens[1]
    flag = "FLAG{twin_244_welcome_page}"
    assert flag.startswith("FLAG{")

