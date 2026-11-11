"""Web exploitation and testing modules."""

from ctf_toolkit.web.helpers import (
    b64url_decode,
    b64url_encode,
    build_basic_auth,
    build_cors_null_origin_headers,
    build_graphql_query,
    build_http_parameter_pollution_query,
    build_jsonp_callback_url,
    build_nosql_query_payload,
    build_ssti_probes,
    format_cookies,
    jwt_decode_no_verify,
    jwt_forge_alg_none,
    jwt_forge_hs256,
    merge_mass_assignment,
    parse_cookies,
    parse_swagger_spec,
    url_decode,
    url_encode,
)
from ctf_toolkit.web.robots import parse_robots_txt
from ctf_toolkit.web.traversal import check_lfi_disclosure, generate_traversal_payloads
from ctf_toolkit.web.cheatsheets import WEB_CHEATSHEETS, get_web_cheatsheet, format_cheatsheet_text

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
    "jwt_forge_alg_none",
    "build_basic_auth",
    "parse_cookies",
    "format_cookies",
    "build_nosql_query_payload",
    "build_graphql_query",
    "build_ssti_probes",
    "merge_mass_assignment",
    "build_http_parameter_pollution_query",
    "parse_swagger_spec",
    "build_jsonp_callback_url",
    "build_cors_null_origin_headers",
    "WEB_CHEATSHEETS",
    "get_web_cheatsheet",
    "format_cheatsheet_text",
]
