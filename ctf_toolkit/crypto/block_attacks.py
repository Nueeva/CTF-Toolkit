from __future__ import annotations

from typing import Callable


def cbc_bitflip_craft(
    iv_or_prev_block: bytes,
    current_plaintext: bytes,
    target_plaintext: bytes,
) -> bytes:
    """
    Compute a modified IV or previous ciphertext block for AES/DES CBC bit-flipping
    so that the decrypted next block changes from `current_plaintext` to `target_plaintext`.
    """
    if len(current_plaintext) != len(target_plaintext):
        raise ValueError("current_plaintext and target_plaintext must have equal length")
    if len(current_plaintext) > len(iv_or_prev_block):
        raise ValueError("plaintext length cannot exceed block size")

    out = bytearray(iv_or_prev_block)
    for i in range(len(current_plaintext)):
        out[i] ^= current_plaintext[i] ^ target_plaintext[i]
    return bytes(out)


def ecb_byte_at_a_time_recover(
    oracle_fn: Callable[[bytes], bytes],
    block_size: int = 16,
    max_bytes: int = 64,
) -> bytes:
    """
    Recover secret suffix from an chosen-prefix AES-ECB encryption oracle `E(attacker_prefix || secret)`.
    """
    recovered = bytearray()
    for i in range(max_bytes):
        pad_len = (block_size - 1 - (len(recovered) % block_size)) % block_size
        prefix = b"A" * pad_len
        block_idx = len(recovered) // block_size
        block_start = block_idx * block_size
        block_end = block_start + block_size

        target_block = oracle_fn(prefix)[block_start:block_end]
        found_byte: int | None = None
        for b in range(256):
            probe = prefix + bytes(recovered) + bytes([b])
            if oracle_fn(probe)[block_start:block_end] == target_block:
                found_byte = b
                break
        if found_byte is None or found_byte == 1:
            break
        recovered.append(found_byte)
    return bytes(recovered)


def gcm_gf128_mul(x: int, y: int) -> int:
    """Multiply two 128-bit elements in NIST SP 800-38D GHASH field GF(2^128)."""
    R = 0xE1000000000000000000000000000000
    z = 0
    v = x & ((1 << 128) - 1)
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ R
        else:
            v >>= 1
    return z


def gcm_ghash_compute(h_key: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    """Compute 16-byte AES-GCM GHASH digest given 16-byte authentication subkey H, AAD, and ciphertext."""
    if len(h_key) != 16:
        raise ValueError("GHASH subkey H must be exactly 16 bytes")
    h_int = int.from_bytes(h_key, "big")

    def _pad16(data: bytes) -> bytes:
        rem = len(data) % 16
        return data + (b"\x00" * ((16 - rem) % 16))

    lengths_block = ((len(aad) * 8) << 64) | (len(ciphertext) * 8)
    stream = _pad16(aad) + _pad16(ciphertext) + lengths_block.to_bytes(16, "big")

    y = 0
    for i in range(0, len(stream), 16):
        block_int = int.from_bytes(stream[i : i + 16], "big")
        y = gcm_gf128_mul(y ^ block_int, h_int)
    return y.to_bytes(16, "big")


def gcm_nonce_reuse_verify_h(
    h_candidate: bytes,
    aad1: bytes,
    ct1: bytes,
    tag1: bytes,
    aad2: bytes,
    ct2: bytes,
    tag2: bytes,
) -> bool:
    """Verify if `h_candidate` is the true AES-GCM GHASH key H for two messages encrypted under a reused nonce."""
    g1 = int.from_bytes(gcm_ghash_compute(h_candidate, aad1, ct1), "big")
    g2 = int.from_bytes(gcm_ghash_compute(h_candidate, aad2, ct2), "big")
    t1 = int.from_bytes(tag1, "big")
    t2 = int.from_bytes(tag2, "big")
    return (g1 ^ g2) == (t1 ^ t2)


def gcm_forge_tag_with_h(
    h_key: bytes,
    known_aad: bytes,
    known_ct: bytes,
    known_tag: bytes,
    target_aad: bytes,
    target_ct: bytes,
) -> bytes:
    """Compute a valid 16-byte AES-GCM authentication tag for `(target_aad, target_ct)` under a reused nonce using recovered GHASH subkey `h_key`."""
    g_known = int.from_bytes(gcm_ghash_compute(h_key, known_aad, known_ct), "big")
    t_known = int.from_bytes(known_tag, "big")
    enc_j0 = t_known ^ g_known
    g_target = int.from_bytes(gcm_ghash_compute(h_key, target_aad, target_ct), "big")
    return (g_target ^ enc_j0).to_bytes(16, "big")
