from __future__ import annotations

from collections import Counter

from ctf_toolkit.utils.math import gcd, modinv


def rot_n(text: str, shift: int) -> str:
    result: list[str] = []
    for ch in text:
        if "a" <= ch <= "z":
            result.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            result.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
        else:
            result.append(ch)
    return "".join(result)


def caesar_encrypt(text: str, shift: int) -> str:
    return rot_n(text, shift)


def caesar_decrypt(text: str, shift: int) -> str:
    return rot_n(text, -shift)


def caesar_bruteforce(text: str) -> list[tuple[int, str]]:
    return [(shift, caesar_decrypt(text, shift)) for shift in range(26)]


def atbash(text: str) -> str:
    out: list[str] = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr(ord("z") - (ord(ch) - ord("a"))))
        elif "A" <= ch <= "Z":
            out.append(chr(ord("Z") - (ord(ch) - ord("A"))))
        else:
            out.append(ch)
    return "".join(out)


def _vig_shift(ch: str) -> int:
    return ord(ch.upper()) - ord("A")


def vigenere_encrypt(text: str, key: str) -> str:
    clean_key = [k for k in key if k.isalpha()]
    if not clean_key:
        raise ValueError("Vigenere key must contain letters")

    out: list[str] = []
    j = 0
    for ch in text:
        if ch.isalpha():
            shift = _vig_shift(clean_key[j % len(clean_key)])
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base + shift) % 26 + base))
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def vigenere_decrypt(text: str, key: str) -> str:
    clean_key = [k for k in key if k.isalpha()]
    if not clean_key:
        raise ValueError("Vigenere key must contain letters")

    out: list[str] = []
    j = 0
    for ch in text:
        if ch.isalpha():
            shift = _vig_shift(clean_key[j % len(clean_key)])
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base - shift) % 26 + base))
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def affine_encrypt(text: str, a: int, b: int) -> str:
    if gcd(a, 26) != 1:
        raise ValueError("a must be coprime with 26")

    out: list[str] = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            x = ord(ch) - base
            out.append(chr((a * x + b) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


def affine_decrypt(text: str, a: int, b: int) -> str:
    if gcd(a, 26) != 1:
        raise ValueError("a must be coprime with 26")
    a_inv = modinv(a, 26)

    out: list[str] = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            y = ord(ch) - base
            out.append(chr((a_inv * (y - b)) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


def apply_substitution(text: str, mapping: dict[str, str]) -> str:
    out: list[str] = []
    for ch in text:
        if ch.isalpha():
            src = ch.upper()
            dst = mapping.get(src, src)
            out.append(dst if ch.isupper() else dst.lower())
        else:
            out.append(ch)
    return "".join(out)


def frequency_analysis(text: str) -> list[tuple[str, int]]:
    letters = [c.upper() for c in text if c.isalpha()]
    return Counter(letters).most_common()
