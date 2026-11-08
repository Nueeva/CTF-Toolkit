from __future__ import annotations

import re


def decode_zero_width(text: str) -> bytes:
    """Decode zero-width spaces (\u200b=0, \u200c=1) to bytes."""
    bits: list[str] = []
    for ch in text:
        if ch == "\u200b":
            bits.append("0")
        elif ch == "\u200c":
            bits.append("1")
    bit_str = "".join(bits)
    byte_vals = [
        int(bit_str[i : i + 8], 2)
        for i in range(0, len(bit_str), 8)
        if len(bit_str[i : i + 8]) == 8
    ]
    return bytes(byte_vals)


def encode_zero_width(data: bytes) -> str:
    """Encode bytes into zero-width characters (\u200b and \u200c)."""
    out: list[str] = []
    for b in data:
        bits = f"{b:08b}"
        for bit in bits:
            out.append("\u200c" if bit == "1" else "\u200b")
    return "".join(out)


def decode_trailing_whitespace(lines: list[str]) -> bytes:
    """Extract trailing tabs (1) and spaces (0) from line endings to bytes."""
    bits: list[str] = []
    for line in lines:
        m = re.search(r"[\t ]+$", line.rstrip("\r\n"))
        if m:
            for ch in m.group(0):
                bits.append("1" if ch == "\t" else "0")
    bit_str = "".join(bits)
    byte_vals = [
        int(bit_str[i : i + 8], 2)
        for i in range(0, len(bit_str), 8)
        if len(bit_str[i : i + 8]) == 8
    ]
    return bytes(byte_vals)


def decode_unicode_tag_plane(text: str) -> str:
    """Extract invisible ASCII characters encoded in Unicode Tag Plane (U+E0000..U+E007F)."""
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            out.append(chr(cp - 0xE0000))
    return "".join(out)


SEVEN_SEG_MAP: dict[str, str] = {
    "abcdef": "0",
    "bc": "1",
    "abdeg": "2",
    "abcdg": "3",
    "bcfg": "4",
    "acdfg": "5",
    "acdefg": "6",
    "abc": "7",
    "abcdefg": "8",
    "abcdfg": "9",
    "abcefg": "a",
    "cdefg": "b",
    "adef": "c",
    "bcdeg": "d",
    "adefg": "e",
    "aefg": "f",
}

SEVEN_SEG_MASK_MAP: dict[int, str] = {
    0x3F: "0",
    0x06: "1",
    0x5B: "2",
    0x4F: "3",
    0x66: "4",
    0x6D: "5",
    0x7D: "6",
    0x07: "7",
    0x7F: "8",
    0x6F: "9",
    0x77: "a",
    0x7C: "b",
    0x39: "c",
    0x5E: "d",
    0x79: "e",
    0x71: "f",
}


def decode_seven_segment(states: list[int | str] | str) -> str:
    """
    Decode 7-segment display states (either segment strings like 'abcdef' or 7-bit masks like 0x3f).
    """
    tokens = states.split() if isinstance(states, str) else states
    decoded: list[str] = []
    for tok in tokens:
        if isinstance(tok, int) or (isinstance(tok, str) and (tok.startswith("0x") or tok.isdigit())):
            val = int(tok, 0) if isinstance(tok, str) else tok
            if val in SEVEN_SEG_MASK_MAP:
                decoded.append(SEVEN_SEG_MASK_MAP[val])
            elif 32 <= val <= 126:
                decoded.append(chr(val))
        else:
            key = "".join(sorted(str(tok).lower()))
            if key in SEVEN_SEG_MAP:
                decoded.append(SEVEN_SEG_MAP[key])
    raw = "".join(decoded)
    if len(raw) >= 4 and len(raw) % 2 == 0 and all(c in "0123456789abcdef" for c in raw):
        try:
            as_ascii = bytes.fromhex(raw).decode("utf-8")
            if all(32 <= ord(c) <= 126 for c in as_ascii):
                return as_ascii
        except Exception:
            pass
    return raw


def extract_acrostic(text: str, index: int = 0, by_word: bool = False) -> str:
    """Extract acrostic characters from the N-th position of each line or each word."""
    units = text.split() if by_word else [line.strip() for line in text.splitlines() if line.strip()]
    out = [u[index] for u in units if len(u) > abs(index)]
    return "".join(out)


def extract_periodic_step(text: str, step: int = 5, start: int = 0) -> str:
    """Extract characters at regular periodic step intervals text[start::step]."""
    if step <= 0:
        raise ValueError("step must be positive")
    return text[start::step]


def decode_case_bitstream(text: str, upper_is_one: bool = True) -> bytes:
    """Decode binary steganography hidden in uppercase/lowercase letter casing."""
    bits = []
    for ch in text:
        if ch.isalpha():
            is_one = ch.isupper() if upper_is_one else ch.islower()
            bits.append("1" if is_one else "0")
    bit_str = "".join(bits)
    return bytes(
        int(bit_str[i : i + 8], 2)
        for i in range(0, len(bit_str) - 7, 8)
    )


def reconstruct_from_regex_pattern(pattern: str) -> str:
    """
    Reconstruct literal string from singleton regex patterns such as
    `^GETSFLAG\\{[a][b][c]\\}$` or `\\x47\\x45...`.
    """
    s = pattern.strip()
    if s.startswith("^"):
        s = s[1:]
    if s.endswith("$"):
        s = s[:-1]
    s = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), s)
    s = re.sub(r"\[([^\[\]\\])\]", r"\1", s)
    s = re.sub(r"\\([{}()\[\].+*?^$\\|-])", r"\1", s)
    return s
