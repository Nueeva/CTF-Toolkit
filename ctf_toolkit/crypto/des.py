from __future__ import annotations

from Crypto.Cipher import DES, DES3
from Crypto.Util.Padding import pad as pkcs7_pad, unpad as pkcs7_unpad


def des_ecb_decrypt(ciphertext: bytes, key: bytes, unpad: bool = True) -> bytes:
    """
    Decrypt ciphertext using legacy DES-ECB (64-bit block size) via pycryptodome.
    """
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes (64 bits)")
    if len(ciphertext) % 8 != 0:
        raise ValueError("DES ciphertext must be a multiple of 8 bytes")

    cipher = DES.new(key, DES.MODE_ECB)
    raw = cipher.decrypt(ciphertext)

    if unpad:
        return pkcs7_unpad(raw, 8)
    return raw


def des_ecb_encrypt(plaintext: bytes, key: bytes, pad: bool = True) -> bytes:
    """
    Encrypt plaintext using legacy DES-ECB with PKCS7 padding via pycryptodome.
    """
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes (64 bits)")

    data = pkcs7_pad(plaintext, 8) if pad else plaintext
    if len(data) % 8 != 0:
        raise ValueError("DES plaintext must be a multiple of 8 bytes when pad=False")

    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)


def triple_des_ecb_decrypt(ciphertext: bytes, key: bytes, unpad: bool = True) -> bytes:
    """
    Decrypt ciphertext using 3DES-ECB (16 or 24 byte key).
    """
    if len(key) not in (16, 24):
        raise ValueError("3DES key must be 16 or 24 bytes")
    if len(ciphertext) % 8 != 0:
        raise ValueError("3DES ciphertext must be a multiple of 8 bytes")

    adjusted_key = DES3.adjust_key_parity(key)
    cipher = DES3.new(adjusted_key, DES3.MODE_ECB)
    raw = cipher.decrypt(ciphertext)
    return pkcs7_unpad(raw, 8) if unpad else raw
