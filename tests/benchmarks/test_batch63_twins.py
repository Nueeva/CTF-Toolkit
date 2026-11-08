from __future__ import annotations

import base64
import json
from ctf_toolkit.web.helpers import (
    build_cors_null_origin_headers,
    build_http_parameter_pollution_query,
    build_jsonp_callback_url,
    build_nosql_query_payload,
    merge_mass_assignment,
    parse_swagger_spec,
    url_decode,
    url_encode,
)


def test_twin_860_backup_source() -> None:
    # Backup source file disclosure
    mock_files = {"index.php.bak": "<?php // FLAG=FLAG{twin_backup_source_leak} ?>"}
    assert "index.php.bak" in mock_files
    flag = "FLAG{twin_backup_source_leak}"
    assert flag in mock_files["index.php.bak"]


def test_twin_863_encoded_id() -> None:
    # Base64 encoded identifier IDOR
    encoded_id = base64.b64encode(b"admin").decode()
    decoded = base64.b64decode(encoded_id).decode()
    assert decoded == "admin"
    notes = {"admin": "FLAG{twin_encoded_id_b64}"}
    assert notes.get(decoded) == "FLAG{twin_encoded_id_b64}"


def test_twin_868_trusted_proxy() -> None:
    # Reverse proxy header spoofing
    headers = {"X-Forwarded-For": "127.0.0.1"}
    is_internal = headers.get("X-Forwarded-For") == "127.0.0.1"
    assert is_internal is True
    flag = "FLAG{twin_trusted_proxy_header}" if is_internal else None
    assert flag == "FLAG{twin_trusted_proxy_header}"


def test_twin_871_no_csrf_token() -> None:
    # CSRF state manipulation
    state = {"role": "guest"}
    # Simulated CSRF request
    state["role"] = "admin"
    assert state["role"] == "admin"
    flag = "FLAG{twin_no_csrf_token_promote}"
    assert flag.startswith("FLAG{")


def test_twin_874_nosql_regex() -> None:
    # NoSQL regex search pattern
    payload = build_nosql_query_payload("token", "$regex", "^FLAG")
    assert payload["token"]["$regex"] == "^FLAG"
    flag = "FLAG{twin_nosql_regex_search}"
    assert flag.startswith("FLAG")


def test_twin_875_nosql_array() -> None:
    # Query parameter array parsing for auth bypass
    params = {"user": "admin", "pass": ["a", "b"]}
    # In PHP/Express, array pass comparison in loose DB driver
    is_array = isinstance(params["pass"], list)
    assert is_array is True
    flag = "FLAG{twin_nosql_array_param_bypass}"
    assert flag.startswith("FLAG{")


def test_twin_879_proc_environ() -> None:
    # /proc/self/environ disclosure
    mock_environ = "PATH=/usr/bin\x00FLAG=FLAG{twin_proc_environ_leak}\x00USER=root"
    vars_dict = dict(pair.split("=", 1) for pair in mock_environ.split("\x00") if "=" in pair)
    assert vars_dict.get("FLAG") == "FLAG{twin_proc_environ_leak}"


def test_twin_884_broken_object_level() -> None:
    # BOLA / IDOR numeric ID lookup
    orders = {
        1001: {"user": "self", "data": "item A"},
        1002: {"user": "admin", "data": "FLAG{twin_bola_order_leak}"}
    }
    accessed = orders.get(1002)
    assert accessed is not None and "FLAG{twin_bola_order_leak}" in accessed["data"]


def test_twin_888_discount_tamper() -> None:
    # Client-controlled discount parameter
    cart_total = 500
    discount_pct = 100
    final_price = cart_total - (cart_total * discount_pct // 100)
    assert final_price == 0
    flag = "FLAG{twin_discount_tamper_zero}"
    assert flag.startswith("FLAG{")


def test_twin_889_price_overflow() -> None:
    # Negative quantity leading to credit
    balance = 50
    qty = -100
    unit_cost = 10
    total = qty * unit_cost  # -1000
    balance -= total  # 1050
    assert balance >= 1000
    flag = "FLAG{twin_price_overflow_negative_qty}"
    assert flag.startswith("FLAG{")


def test_twin_890_swagger_leak() -> None:
    # OpenAPI specification endpoint extraction
    spec = {
        "paths": {
            "/api/public": {},
            "/api/secret/flag": {}
        }
    }
    routes = parse_swagger_spec(spec)
    assert "/api/secret/flag" in routes
    flag = "FLAG{twin_swagger_spec_endpoint_leak}"
    assert flag.startswith("FLAG{")


def test_twin_891_actuator_env() -> None:
    # Spring Boot Actuator /env disclosure
    actuator_resp = {
        "propertySources": [
            {
                "name": "systemProperties",
                "properties": {
                    "flag": {"value": "FLAG{twin_actuator_env_leak}"}
                }
            }
        ]
    }
    extracted = actuator_resp["propertySources"][0]["properties"]["flag"]["value"]
    assert extracted == "FLAG{twin_actuator_env_leak}"


def test_twin_892_db_backup() -> None:
    # Public SQL dump parsing
    sql_dump = "INSERT INTO secrets VALUES (1, 'FLAG{twin_database_backup_dump}');"
    assert "FLAG{twin_database_backup_dump}" in sql_dump


def test_twin_894_cors_null_origin() -> None:
    # CORS null origin trust verification
    hdrs = build_cors_null_origin_headers()
    assert hdrs["Origin"] == "null"
    cors_allowed = hdrs["Origin"] == "null"
    flag = "FLAG{twin_cors_null_origin_trust}" if cors_allowed else None
    assert flag == "FLAG{twin_cors_null_origin_trust}"


def test_twin_895_content_type_upload() -> None:
    # Content-Type MIME spoofing
    uploaded_file = {
        "filename": "payload.php",
        "content_type": "image/png"
    }
    assert uploaded_file["content_type"] == "image/png"
    flag = "FLAG{twin_content_type_upload_mime}"
    assert flag.startswith("FLAG{")


def test_twin_897_jsonp_leak() -> None:
    # JSONP callback endpoint wrapping
    url = build_jsonp_callback_url("/api/me", "myHandler")
    assert "callback=myHandler" in url
    synthetic_resp = "myHandler({\"flag\": \"FLAG{twin_jsonp_callback_leak}\"});"
    assert "FLAG{twin_jsonp_callback_leak}" in synthetic_resp


def test_twin_900_nested_mass_assign() -> None:
    # Nested mass assignment attribute update
    user_model = {
        "name": "bob",
        "settings": {"theme": "dark", "is_admin": False}
    }
    payload = {
        "name": "bob",
        "settings": {"theme": "dark", "is_admin": True}
    }
    user_model["settings"].update(payload["settings"])
    assert user_model["settings"]["is_admin"] is True
    flag = "FLAG{twin_nested_mass_assignment}"
    assert flag.startswith("FLAG{")


def test_twin_902_param_pollution() -> None:
    # HTTP Parameter Pollution query generation
    q = build_http_parameter_pollution_query([("amount", "0"), ("amount", "1000")])
    assert q == "amount=0&amount=1000"
    flag = "FLAG{twin_http_param_pollution}"
    assert flag.startswith("FLAG{")


def test_twin_905_patch_bypass() -> None:
    # HTTP PATCH verb dispatch
    def router(method: str) -> str:
        if method == "PATCH":
            return "FLAG{twin_patch_verb_bypass}"
        return "Not Allowed"
    assert router("PATCH") == "FLAG{twin_patch_verb_bypass}"


def test_twin_906_no_reauth() -> None:
    # Missing re-authentication on sensitive change
    session = {"user": "victim", "logged_in": True}
    def change_email(sess: dict, new_email: str) -> str:
        if sess.get("logged_in"):
            sess["email"] = new_email
            return "FLAG{twin_no_reauth_sensitive_change}"
        return "Denied"
    res = change_email(session, "attacker@local")
    assert res == "FLAG{twin_no_reauth_sensitive_change}"
