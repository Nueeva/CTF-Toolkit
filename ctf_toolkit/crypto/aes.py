from __future__ import annotations

from Crypto.Cipher import AES


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    if block_size <= 0 or block_size > 255:
        raise ValueError("invalid block_size")
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("invalid data length for unpad")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid padding")
    return data[:-pad_len]


def _normalize_key(key: bytes) -> bytes:
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16/24/32 bytes")
    return key


def aes_ecb_encrypt(plaintext: bytes, key: bytes, use_padding: bool = True) -> bytes:
    """ECB helper for CTF labs only; do not use ECB in real-world systems."""
    key = _normalize_key(key)
    data = pkcs7_pad(plaintext) if use_padding else plaintext
    if len(data) % 16 != 0:
        raise ValueError("plaintext must be a multiple of 16 when padding is disabled")
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)


def aes_ecb_decrypt(ciphertext: bytes, key: bytes, unpad: bool = True) -> bytes:
    """ECB helper for CTF labs only; do not use ECB in real-world systems."""
    key = _normalize_key(key)
    if len(ciphertext) % 16 != 0:
        raise ValueError("ECB ciphertext length must be a multiple of 16")
    plain = AES.new(key, AES.MODE_ECB).decrypt(ciphertext)
    return pkcs7_unpad(plain) if unpad else plain


def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes, use_padding: bool = True) -> bytes:
    key = _normalize_key(key)
    if len(iv) != 16:
        raise ValueError("CBC IV must be 16 bytes")
    data = pkcs7_pad(plaintext) if use_padding else plaintext
    if len(data) % 16 != 0:
        raise ValueError("plaintext must be a multiple of 16 when padding is disabled")
    return AES.new(key, AES.MODE_CBC, iv=iv).encrypt(data)


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes, unpad: bool = True) -> bytes:
    key = _normalize_key(key)
    if len(iv) != 16:
        raise ValueError("CBC IV must be 16 bytes")
    if len(ciphertext) % 16 != 0:
        raise ValueError("CBC ciphertext length must be a multiple of 16")
    plain = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ciphertext)
    return pkcs7_unpad(plain) if unpad else plain


def aes_ctr_crypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    key = _normalize_key(key)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.encrypt(data)


def detect_ecb(ciphertext: bytes, block_size: int = 16) -> tuple[int, int]:
    blocks = [ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)]
    repeats = len(blocks) - len(set(blocks))
    return repeats, len(blocks)
