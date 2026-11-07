from __future__ import annotations

import base64


def fernet_decrypt(token: str | bytes, key: str | bytes) -> bytes:
    """Decrypt a Fernet token (AES-128-CBC + HMAC-SHA256) given a 32-byte URL-safe base64 key."""
    t_bytes = token.encode("utf-8") if isinstance(token, str) else token
    k_bytes = key.encode("utf-8") if isinstance(key, str) else key

    try:
        from cryptography.fernet import Fernet

        f = Fernet(k_bytes)
        return f.decrypt(t_bytes)
    except ImportError:
        # Fallback to manual cryptography primitives if needed
        import hmac
        import hashlib
        from Crypto.Cipher import AES

        raw_key = base64.urlsafe_b64decode(k_bytes)
        signing_key = raw_key[:16]
        encryption_key = raw_key[16:]

        raw_token = base64.urlsafe_b64decode(t_bytes)
        version = raw_token[0]
        timestamp = raw_token[1:9]
        iv = raw_token[9:25]
        ciphertext = raw_token[25:-32]
        expected_hmac = raw_token[-32:]

        computed_hmac = hmac.new(signing_key, raw_token[:-32], hashlib.sha256).digest()
        if not hmac.compare_digest(computed_hmac, expected_hmac):
            raise ValueError("Invalid Fernet HMAC signature")

        cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
        padded = cipher.decrypt(ciphertext)
        pad_len = padded[-1]
        return padded[:-pad_len]
