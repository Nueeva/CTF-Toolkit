from __future__ import annotations

import re

from ctf_toolkit.utils.parse import parse_int


def validate_alphabet(alphabet: str) -> str:
    cleaned = alphabet.strip()
    if not cleaned:
        raise ValueError("alphabet tidak boleh kosong")
    if len(set(cleaned)) != len(cleaned):
        raise ValueError("alphabet harus unik (tidak boleh ada karakter duplikat)")
    if len(cleaned) < 2:
        raise ValueError("alphabet minimal 2 karakter")
    return cleaned


def parse_custom_key(raw: str, alphabet: str) -> list[int]:
    text = raw.strip()
    if not text:
        raise ValueError("key tidak boleh kosong")
    tokens = [tok for tok in re.split(r"[,\s]+", text) if tok]
    if len(tokens) > 1 or re.fullmatch(r"-?0x[0-9a-fA-F]+|-?\d+", text):
        return [parse_int(token) for token in tokens]
    if all(ch in alphabet for ch in text):
        return [alphabet.index(ch) for ch in text]
    raise ValueError("key harus berupa angka atau string yang ada di alphabet")


def _normalize_shifts(shifts: list[int], size: int) -> list[int]:
    if not shifts:
        raise ValueError("key shift kosong")
    return [shift % size for shift in shifts]


def _apply_index(idx: int, shift: int, size: int, mode: str) -> int:
    if mode == "xor":
        return (idx ^ shift) % size
    return (idx - shift) % size


def apply_custom_cipher(text: str, alphabet: str, shifts: list[int], mode: str = "shift") -> str:
    mapping = {ch: idx for idx, ch in enumerate(alphabet)}
    size = len(alphabet)
    norm_shifts = _normalize_shifts(shifts, size)
    out: list[str] = []
    shift_len = len(norm_shifts)
    for idx, ch in enumerate(text):
        if ch not in mapping:
            out.append(ch)
            continue
        pos = mapping[ch]
        shift = norm_shifts[idx % shift_len]
        out.append(alphabet[_apply_index(pos, shift, size, mode)])
    return "".join(out)


def bruteforce_custom_cipher(text: str, alphabet: str, mode: str = "shift") -> list[tuple[int, str]]:
    size = len(alphabet)
    return [(shift, apply_custom_cipher(text, alphabet, [shift], mode=mode)) for shift in range(size)]
