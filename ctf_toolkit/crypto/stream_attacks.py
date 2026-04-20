from __future__ import annotations

from typing import Iterable


def xor_prefix(left: bytes, right: bytes) -> bytes:
    size = min(len(left), len(right))
    return bytes(left[idx] ^ right[idx] for idx in range(size))


def keystream_from_known_pair(ciphertext: bytes, plaintext: bytes) -> bytes:
    return xor_prefix(ciphertext, plaintext)


def merge_keystreams(keystreams: Iterable[bytes]) -> list[int | None]:
    streams = list(keystreams)
    if not streams:
        raise ValueError("at least one keystream is required")

    merged: list[int | None] = [None] * max(len(stream) for stream in streams)
    for stream in streams:
        for idx, value in enumerate(stream):
            current = merged[idx]
            if current is None:
                merged[idx] = value
            elif current != value:
                raise ValueError(f"keystream conflict at offset {idx}")
    return merged


def decrypt_with_partial_keystream(ciphertext: bytes, keystream: list[int | None]) -> tuple[bytes, list[bool]]:
    plain = bytearray()
    known_mask: list[bool] = []
    for idx, value in enumerate(ciphertext):
        if idx < len(keystream) and keystream[idx] is not None:
            plain.append(value ^ keystream[idx])
            known_mask.append(True)
        else:
            plain.append(0)
            known_mask.append(False)
    return bytes(plain), known_mask


def masked_utf8_view(data: bytes, known_mask: list[bool], unknown_char: str = ".") -> str:
    if len(unknown_char) != 1:
        raise ValueError("unknown_char must be a single character")
    unknown_byte = unknown_char.encode("utf-8", errors="ignore")
    if len(unknown_byte) != 1:
        raise ValueError("unknown_char must map to exactly one byte")
    mapped = bytes(byte if known else unknown_byte[0] for byte, known in zip(data, known_mask))
    return mapped.decode("utf-8", errors="ignore")
