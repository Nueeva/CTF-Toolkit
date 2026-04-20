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
        raise ValueError("minimal satu pasangan known plaintext/ciphertext diperlukan")

    merged: list[int | None] = [None] * max(len(stream) for stream in streams)
    for stream in streams:
        for idx, value in enumerate(stream):
            current = merged[idx]
            if current is None:
                merged[idx] = value
            elif current != value:
                raise ValueError(f"konflik keystream pada offset {idx}")
    return merged


def decrypt_with_partial_keystream(ciphertext: bytes, keystream: list[int | None]) -> tuple[bytes, list[bool]]:
    plain = bytearray()
    known_mask: list[bool] = []
    for idx, value in enumerate(ciphertext):
        if idx < len(keystream) and keystream[idx] is not None:
            plain.append(value ^ int(keystream[idx]))
            known_mask.append(True)
        else:
            plain.append(0)
            known_mask.append(False)
    return bytes(plain), known_mask


def masked_utf8_view(data: bytes, known_mask: list[bool], unknown_char: str = ".") -> str:
    if len(unknown_char) != 1:
        raise ValueError("unknown_char harus satu karakter")
    rendered = "".join(chr(byte) if known else unknown_char for byte, known in zip(data, known_mask))
    return rendered.encode("latin-1", errors="ignore").decode("utf-8", errors="ignore")
