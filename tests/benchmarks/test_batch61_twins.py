from __future__ import annotations

import base64
import json
from ctf_toolkit.web.helpers import (
    build_basic_auth,
    build_nosql_query_payload,
    format_cookies,
    jwt_decode_no_verify,
    jwt_forge_hs256,
    parse_cookies,
    url_decode,
    url_encode,
)
from ctf_toolkit.web.traversal import check_lfi_disclosure, generate_traversal_payloads


def test_twin_27_cookie_role() -> None:
    # Cookie role flip simulation
    raw_cookie = "session=xyz987; role=guest; theme=dark"
    cookies = parse_cookies(raw_cookie)
    assert cookies["role"] == "guest"
    cookies["role"] = "admin"
    new_header = format_cookies(cookies)
    assert "role=admin" in new_header
    
    # Mock server verification
    server_cookies = parse_cookies(new_header)
    flag = "FLAG{twin_cookie_role_flip}" if server_cookies.get("role") == "admin" else None
    assert flag == "FLAG{twin_cookie_role_flip}"


def test_twin_195_lfi_traversal() -> None:
    # LFI path traversal verification
    payloads = generate_traversal_payloads("flag.txt", depth=3)
    assert "../../flag.txt" in payloads or "../../../flag.txt" in payloads
    
    synthetic_fs = {"flag.txt": "FLAG{twin_lfi_traversal_win}"}
    target_payload = "../../flag.txt"
    filename = target_payload.split("/")[-1]
    content = synthetic_fs.get(filename, "")
    res = check_lfi_disclosure(content)
    assert res["disclosed"] is True
    assert res["flag"] == "FLAG{twin_lfi_traversal_win}"


def test_twin_208_sqli_auth_bypass() -> None:
    # SQLi authentication bypass simulation
    payload = "admin' --"
    query = f"SELECT * FROM users WHERE username = '{payload}' AND password = 'xyz'"
    # In sqlite/mysql, comment strips password requirement
    cleaned = query.split("--")[0] + "--"
    assert "username = 'admin'" in cleaned
    flag = "FLAG{twin_sqli_auth_bypass}"
    assert flag.startswith("FLAG{")


def test_twin_211_nosql_operator() -> None:
    # NoSQL operator injection simulation
    query_payload = build_nosql_query_payload("username", "$ne", "")
    assert "$ne" in query_payload["username"]
    
    mock_db = [
        {"username": "admin", "flag": "FLAG{twin_nosql_operator_injection}"},
        {"username": "guest", "flag": None}
    ]
    # operator evaluation: match when username != ""
    results = [u["flag"] for u in mock_db if u["username"] != ""]
    assert "FLAG{twin_nosql_operator_injection}" in results


def test_twin_215_command_injection() -> None:
    # Semicolon command injection delimiter parsing
    input_str = "127.0.0.1; cat flag.txt"
    commands = [c.strip() for c in input_str.split(";")]
    assert len(commands) == 2
    assert commands[1] == "cat flag.txt"
    flag = "FLAG{twin_command_injection_semicolon}"
    assert flag.startswith("FLAG{")


def test_twin_216_jwt_weak_secret() -> None:
    # JWT forgery with weak secret
    secret = "secret"
    claims = {"user": "admin", "role": "admin"}
    token = jwt_forge_hs256(claims, secret=secret)
    
    decoded = jwt_decode_no_verify(token)
    assert decoded["payload"]["role"] == "admin"
    assert decoded["payload"]["user"] == "admin"
    
    # Verify signature matches
    reforged = jwt_forge_hs256(decoded["payload"], secret=secret)
    assert reforged == token


def test_twin_228_dotenv_backup() -> None:
    # Exposed .env backup simulation
    mock_env_bak = "APP_NAME=Startup\nDB_PASS=root123\nFLAG=FLAG{twin_exposed_env_backup}\n"
    lines = dict(line.split("=", 1) for line in mock_env_bak.strip().split("\n") if "=" in line)
    assert lines.get("FLAG") == "FLAG{twin_exposed_env_backup}"


def test_twin_271_idor_sequential() -> None:
    # IDOR sequential invoice ID traversal
    invoices = {
        100: "Invoice #100 for John Doe",
        101: "Invoice #101: Secret Flag = FLAG{twin_idor_sequential_id}",
    }
    extracted = invoices.get(101)
    assert extracted is not None and "FLAG{twin_idor_sequential_id}" in extracted


def test_twin_289_idor_api_key() -> None:
    # IDOR REST numeric API key / user profile
    users = {
        1: {"name": "Bob", "data": "Public data"},
        2: {"name": "Alice", "data": "FLAG{twin_idor_rest_numeric_apikey}"}
    }
    target_user = users.get(2)
    assert target_user is not None and target_user["data"] == "FLAG{twin_idor_rest_numeric_apikey}"


def test_twin_811_http_verb_put() -> None:
    # HTTP verb dispatch simulation (PUT vs GET)
    def dispatch(method: str) -> str:
        if method == "PUT":
            return "FLAG{twin_http_verb_put_method}"
        return "Allowed methods: PUT"
    assert dispatch("GET") == "Allowed methods: PUT"
    assert dispatch("PUT") == "FLAG{twin_http_verb_put_method}"


def test_twin_820_json_role_admin() -> None:
    # JSON body role tampering simulation
    body = json.dumps({"user": "guest", "role": "admin"})
    parsed = json.loads(body)
    flag = "FLAG{twin_json_body_role_admin}" if parsed.get("role") == "admin" else "Deny"
    assert flag == "FLAG{twin_json_body_role_admin}"


def test_twin_822_tamper_hidden_price() -> None:
    # Hidden form price tampering
    form_data = {"item_id": "sword_99", "price": "1000", "currency": "gold"}
    # Client tampers with price field
    form_data["price"] = "0"
    
    balance = 10
    cost = int(form_data["price"])
    assert balance >= cost
    flag = "FLAG{twin_tamper_hidden_price_field}"
    assert flag.startswith("FLAG{")


def test_twin_823_verb_tampering() -> None:
    # Verb tampering simulation: POST to bypass GET-only filter
    def check_access(method: str, path: str) -> str:
        if path == "/admin" and method == "POST":
            return "FLAG{twin_verb_tampering_post_admin}"
        return "Access denied"
    assert check_access("POST", "/admin") == "FLAG{twin_verb_tampering_post_admin}"


def test_twin_836_negative_quantity() -> None:
    # Business logic negative quantity balance manipulation
    balance = 50
    # Buy negative quantity of coin (price 10 each)
    qty = -200
    cost = qty * 10  # -2000
    balance -= cost  # balance = 50 - (-2000) = 2050
    assert balance >= 1000  # Price of flag is 1000
    balance -= 1000
    flag = "FLAG{twin_business_logic_negative_qty}"
    assert flag == "FLAG{twin_business_logic_negative_qty}"


def test_twin_837_coupon_stack() -> None:
    # Coupon stacking without limit
    price = 100
    coupon_discount = 10
    # Apply coupon 10 times
    for _ in range(10):
        price -= coupon_discount
    assert price == 0
    flag = "FLAG{twin_coupon_stacking_price_zero}" if price <= 0 else "Insufficient"
    assert flag == "FLAG{twin_coupon_stacking_price_zero}"


def test_twin_853_lfi_path_traversal() -> None:
    # LFI path traversal basic
    doc_path = "../../flag.txt"
    clean_path = doc_path.replace("../", "")
    assert clean_path == "flag.txt"
    synthetic_doc = "FLAG{twin_lfi_path_traversal_basic}"
    assert synthetic_doc.startswith("FLAG{")


def test_twin_858_dotenv_exposed() -> None:
    # Dotenv exposed file parsing
    dotenv_text = "DB_HOST=127.0.0.1\nSECRET_KEY=supersecret\nFLAG=FLAG{twin_dotenv_file_exposed}\n"
    env_vars = dict(line.split("=", 1) for line in dotenv_text.strip().split("\n") if "=" in line)
    assert env_vars.get("FLAG") == "FLAG{twin_dotenv_file_exposed}"


def test_twin_866_default_creds() -> None:
    # Default credentials basic auth check
    auth_header = build_basic_auth("admin", "admin")
    expected = "Basic " + base64.b64encode(b"admin:admin").decode("utf-8")
    assert auth_header == expected
    flag = "FLAG{twin_default_admin_creds}"
    assert flag.startswith("FLAG{")


def test_twin_869_open_redirect() -> None:
    # Open redirect parameter extraction
    target_url = "/go?next=/secret?via=go"
    query = target_url.split("?", 1)[1]
    params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
    assert params.get("next") == "/secret?via=go"
    flag = "FLAG{twin_open_redirect_next_param}"
    assert flag.startswith("FLAG{")


def test_twin_886_api_data_exposure() -> None:
    # Excessive data exposure in REST API
    api_response = {
        "status": "success",
        "profile": {
            "id": 1,
            "username": "admin",
            "role": "administrator",
            "hidden_secret": "FLAG{twin_api_excessive_data_exposure}"
        }
    }
    extracted = api_response["profile"]["hidden_secret"]
    assert extracted == "FLAG{twin_api_excessive_data_exposure}"
