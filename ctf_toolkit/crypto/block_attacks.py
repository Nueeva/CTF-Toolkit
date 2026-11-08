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
