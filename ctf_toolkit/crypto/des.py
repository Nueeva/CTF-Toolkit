from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def des_ecb_decrypt(ciphertext: bytes, key: bytes, unpad: bool = True) -> bytes:
    """
    Decrypt ciphertext using legacy DES-ECB (64-bit block size).
    Implemented via TripleDES(key * 3) for standard modern cryptography compatibility.
    """
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes (64 bits)")
    if len(ciphertext) % 8 != 0:
        raise ValueError("DES ciphertext must be a multiple of 8 bytes")

    cipher = Cipher(algorithms.TripleDES(key * 3), modes.ECB())
    decryptor = cipher.decryptor()
    raw = decryptor.update(ciphertext) + decryptor.finalize()

    if unpad:
        unpadder = padding.PKCS7(64).unpadder()
        return unpadder.update(raw) + unpadder.finalize()
    return raw


def des_ecb_encrypt(plaintext: bytes, key: bytes, pad: bool = True) -> bytes:
    """
    Encrypt plaintext using legacy DES-ECB with PKCS7 padding.
    """
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes (64 bits)")

    data = plaintext
    if pad:
        padder = padding.PKCS7(64).padder()
        data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.TripleDES(key * 3), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()
