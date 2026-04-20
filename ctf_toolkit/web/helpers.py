from __future__ import annotations

import base64
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
        header = json.loads(b64url_decode(parts[0]).decode("utf-8", errors="ignore") or "{}")
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid JWT header format") from exc
    try:
        payload = json.loads(b64url_decode(parts[1]).decode("utf-8", errors="ignore") or "{}")
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid JWT payload format") from exc
    signature = parts[2] if len(parts) > 2 else ""
    return {
        "header": header,
        "payload": payload,
        "signature_b64url": signature,
    }
