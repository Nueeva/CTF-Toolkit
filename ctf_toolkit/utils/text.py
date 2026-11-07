from __future__ import annotations

import math
import re
from collections import Counter

ASCII_PRINTABLE_START = 32
ASCII_PRINTABLE_END = 126


def redact_sensitive_text(text: str) -> str:
    redacted = re.sub(r"(?i)(password\s*[=:]\s*)([^\s&]+)", r"\1[REDACTED]", text)
    redacted = re.sub(r"(?i)(token\s*[=:]\s*)([^\s&]+)", r"\1[REDACTED]", redacted)
    redacted = re.sub(r"(?i)(secret\s*[=:]\s*)([^\s&]+)", r"\1[REDACTED]", redacted)
    redacted = re.sub(r'(?i)("password"\s*:\s*")[^"]*(")', r"\1[REDACTED]\2", redacted)
    redacted = re.sub(r'(?i)("token"\s*:\s*")[^"]*(")', r"\1[REDACTED]\2", redacted)
    redacted = re.sub(r"(?i)(authorization\s*:\s*bearer\s+)[^\s]+", r"\1[REDACTED]", redacted)
    return redacted


def extract_printable_strings(raw_bytes: bytes, min_len: int = 4) -> list[str]:
    results: list[str] = []
    current: list[str] = []
    for b in raw_bytes:
        if ASCII_PRINTABLE_START <= b <= ASCII_PRINTABLE_END:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                results.append("".join(current))
            current = []
    if len(current) >= min_len:
        results.append("".join(current))
    return results


def hexdump(data: bytes, width: int = 16) -> str:
    lines: list[str] = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset:08x}  {hex_part:<{width*3}}  {ascii_part}")
    return "\n".join(lines)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


BASE45_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def base45_decode(s: str) -> bytes:
    """Decode a Base45 (RFC 9285) encoded string into bytes."""
    res = bytearray()
    for i in range(0, len(s), 3):
        chunk = s[i : i + 3]
        if len(chunk) == 3:
            c0, c1, c2 = [BASE45_CHARSET.index(c) for c in chunk]
            val = c0 + c1 * 45 + c2 * 45 * 45
            res.append(val // 256)
            res.append(val % 256)
        elif len(chunk) == 2:
            c0, c1 = [BASE45_CHARSET.index(c) for c in chunk]
            val = c0 + c1 * 45
            res.append(val)
        else:
            raise ValueError(f"Invalid Base45 chunk length at index {i}")
    return bytes(res)


def base45_encode(data: bytes) -> str:
    """Encode bytes into a Base45 (RFC 9285) string."""
    res: list[str] = []
    for i in range(0, len(data), 2):
        chunk = data[i : i + 2]
        if len(chunk) == 2:
            val = chunk[0] * 256 + chunk[1]
            c0 = val % 45
            c1 = (val // 45) % 45
            c2 = val // (45 * 45)
            res.extend([BASE45_CHARSET[c0], BASE45_CHARSET[c1], BASE45_CHARSET[c2]])
        else:
            val = chunk[0]
            c0 = val % 45
            c1 = val // 45
            res.extend([BASE45_CHARSET[c0], BASE45_CHARSET[c1]])
    return "".join(res)


Z85_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
_Z85_MAP = {c: i for i, c in enumerate(Z85_ALPHABET)}


def z85_decode(s: str) -> bytes:
    """Decode a ZeroMQ Z85 encoded ASCII string into bytes."""
    if len(s) % 5 != 0:
        raise ValueError("Z85 string length must be a multiple of 5")
    out = bytearray()
    for i in range(0, len(s), 5):
        chunk = s[i : i + 5]
        val = 0
        for c in chunk:
            if c not in _Z85_MAP:
                raise ValueError(f"Invalid character '{c}' in Z85 string")
            val = val * 85 + _Z85_MAP[c]
        out.extend(val.to_bytes(4, "big"))
    return bytes(out)


def z85_encode(data: bytes) -> str:
    """Encode bytes into a ZeroMQ Z85 ASCII string."""
    if len(data) % 4 != 0:
        raise ValueError("Z85 input data length must be a multiple of 4 bytes")
    chars: list[str] = []
    for i in range(0, len(data), 4):
        val = int.from_bytes(data[i : i + 4], "big")
        chunk_chars = [""] * 5
        for j in range(4, -1, -1):
            chunk_chars[j] = Z85_ALPHABET[val % 85]
            val //= 85
        chars.extend(chunk_chars)
    return "".join(chars)


PERIODIC_TABLE_ATOMIC = {
    "H": 1, "He": 2, "Li": 3, "Be": 4, "B": 5, "C": 6, "N": 7, "O": 8, "F": 9, "Ne": 10,
    "Na": 11, "Mg": 12, "Al": 13, "Si": 14, "P": 15, "S": 16, "Cl": 17, "Ar": 18, "K": 19, "Ca": 20,
    "Sc": 21, "Ti": 22, "V": 23, "Cr": 24, "Mn": 25, "Fe": 26, "Co": 27, "Ni": 28, "Cu": 29, "Zn": 30
}


def chem_elements_to_bytes(symbols: list[str] | str) -> bytes:
    """Decode periodic table chemical element symbols (1-based hex nibbles) to bytes."""
    if isinstance(symbols, str):
        sym_list = symbols.strip().split()
    else:
        sym_list = symbols

    nums = [PERIODIC_TABLE_ATOMIC[s] for s in sym_list]
    if len(nums) % 2 != 0:
        raise ValueError("Symbol list length must be even to form byte pairs")

    out = bytearray()
    for i in range(0, len(nums), 2):
        high = (nums[i] - 1) & 0x0F
        low = (nums[i + 1] - 1) & 0x0F
        out.append((high << 4) | low)
    return bytes(out)


ROMAN_NUMERAL_MAP = {"I": 1, "V": 5, "X": 10, "L": 50, "C": 100, "D": 500, "M": 1000}


def roman_to_int(s: str) -> int:
    """Convert standard Roman numeral string to an integer."""
    s = s.strip().upper()
    val = 0
    for i in range(len(s)):
        if i + 1 < len(s) and ROMAN_NUMERAL_MAP[s[i]] < ROMAN_NUMERAL_MAP[s[i + 1]]:
            val -= ROMAN_NUMERAL_MAP[s[i]]
        else:
            val += ROMAN_NUMERAL_MAP[s[i]]
    return val


def int_to_roman(num: int) -> str:
    """Convert an integer (1..3999) to Roman numeral string."""
    val_map = [
        (1000, "M"), (900, "CM"), (500, "D"), (400, "CD"),
        (100, "C"), (90, "XC"), (50, "L"), (40, "XL"),
        (10, "X"), (9, "IX"), (5, "V"), (4, "IV"), (1, "I")
    ]
    res: list[str] = []
    for v, sym in val_map:
        while num >= v:
            res.append(sym)
            num -= v
    return "".join(res)


def spreadsheet_col_to_int(col: str) -> int:
    """Convert Excel/Spreadsheet column string (e.g. 'A'->1, 'Z'->26, 'AA'->27) to 1-based integer."""
    num = 0
    for c in col.strip().upper():
        if "A" <= c <= "Z":
            num = num * 26 + (ord(c) - ord("A") + 1)
    return num


def int_to_spreadsheet_col(num: int) -> str:
    """Convert 1-based integer to Excel/Spreadsheet column string (e.g. 1->'A', 27->'AA')."""
    res: list[str] = []
    while num > 0:
        num, rem = divmod(num - 1, 26)
        res.append(chr(ord("A") + rem))
    return "".join(reversed(res))


RESISTOR_COLOR_CODES = {
    "black": 0, "brown": 1, "red": 2, "orange": 3, "yellow": 4,
    "green": 5, "blue": 6, "violet": 7, "gray": 8, "grey": 8, "white": 9,
}


def resistor_colors_to_int(colors: list[str] | str) -> int:
    """Convert resistor color band names (e.g. ['black', 'violet', 'brown']) to integer value."""
    if isinstance(colors, str):
        c_list = colors.lower().replace(",", " ").split()
    else:
        c_list = [c.lower() for c in colors]
    digits = [str(RESISTOR_COLOR_CODES[c]) for c in c_list if c in RESISTOR_COLOR_CODES]
    return int("".join(digits)) if digits else 0


def dna_to_bytes(seq: str, mapping: dict[str, int] | None = None) -> bytes:
    """Convert DNA nucleotide sequence (2 bits per base) to bytes using base mapping."""
    if mapping is None:
        mapping = {"A": 0, "C": 1, "G": 2, "T": 3}
    bits = "".join(f"{mapping[c.upper()]:02b}" for c in seq if c.upper() in mapping)
    return bytes([int(bits[i : i + 8], 2) for i in range(0, len(bits) - 7, 8)])


HOMOGLYPH_MAP: dict[str, str] = {
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "Ј": "J", "К": "K", "М": "M",
    "О": "O", "Р": "P", "Ѕ": "S", "Т": "T", "Х": "X", "У": "Y", "Z": "Z",
    "а": "a", "с": "c", "е": "e", "і": "i", "ј": "j", "к": "k", "о": "o", "р": "p", "ѕ": "s",
    "х": "x", "у": "y",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}


def normalize_homoglyphs(text: str, custom_map: dict[str, str] | None = None) -> str:
    """Normalize unicode lookalike homoglyphs (e.g. Cyrillic/Greek letters) to their standard ASCII Latin equivalents."""
    mapping = {**HOMOGLYPH_MAP, **(custom_map or {})}
    return "".join(mapping.get(c, c) for c in text)

