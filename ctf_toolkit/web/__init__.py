"""Web exploitation and testing modules."""

from ctf_toolkit.web.helpers import (
    b64url_decode,
    b64url_encode,
    build_basic_auth,
    build_nosql_query_payload,
    format_cookies,
    jwt_decode_no_verify,
    jwt_forge_hs256,
    parse_cookies,
    url_decode,
    url_encode,
)
from ctf_toolkit.web.robots import parse_robots_txt
from ctf_toolkit.web.traversal import check_lfi_disclosure, generate_traversal_payloads

__all__ = [
    "generate_traversal_payloads",
    "check_lfi_disclosure",
    "parse_robots_txt",
    "url_encode",
    "url_decode",
    "b64url_encode",
    "b64url_decode",
    "jwt_decode_no_verify",
    "jwt_forge_hs256",
    "build_basic_auth",
    "parse_cookies",
    "format_cookies",
    "build_nosql_query_payload",
]
