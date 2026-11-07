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

def a1z26_decode(cipher: str) -> str:
    """Decode A1Z26 positional cipher (e.g. 1-2-3 -> abc or 1 2 3 -> abc)."""
    import re

    nums = [int(n) for n in re.findall(r"\b\d+\b", cipher)]
    return "".join([chr(ord("a") + n - 1) if 1 <= n <= 26 else str(n) for n in nums])


def a1z26_encode(text: str, separator: str = "-") -> str:
    """Encode text to A1Z26 positional numbers (a=1, b=2, ..., z=26)."""
    nums = []
    for ch in text.lower():
        if "a" <= ch <= "z":
            nums.append(str(ord(ch) - ord("a") + 1))
    return separator.join(nums)

def polybius_decode(coords: str) -> str:
    """Decode 5x5 Polybius square coordinates (I=J) into lowercase text."""
    import re

    grid = [
        ["a", "b", "c", "d", "e"],
        ["f", "g", "h", "i", "k"],
        ["l", "m", "n", "o", "p"],
        ["q", "r", "s", "t", "u"],
        ["v", "w", "x", "y", "z"],
    ]
    digits = re.findall(r"\d", coords)
    chars = []
    for i in range(0, len(digits), 2):
        if i + 1 < len(digits):
            r = int(digits[i]) - 1
            c = int(digits[i + 1]) - 1
            if 0 <= r < 5 and 0 <= c < 5:
                chars.append(grid[r][c])
    return "".join(chars)


def polybius_encode(text: str, separator: str = " ") -> str:
    """Encode text into 5x5 Polybius square coordinate pairs (row-column)."""
    grid_map = {
        "a": "11", "b": "12", "c": "13", "d": "14", "e": "15",
        "f": "21", "g": "22", "h": "23", "i": "24", "j": "24", "k": "25",
        "l": "31", "m": "32", "n": "33", "o": "34", "p": "35",
        "q": "41", "r": "42", "s": "43", "t": "44", "u": "45",
        "v": "51", "w": "52", "x": "53", "y": "54", "z": "55",
    }
    pairs = [grid_map[c] for c in text.lower() if c in grid_map]
    return separator.join(pairs)


def gronsfeld_encrypt(text: str, key: str | list[int] | int) -> str:
    """Encrypt text using Gronsfeld cipher (Vigenere with numeric digit keys)."""
    digits = [int(d) for d in str(key) if d.isdigit()]
    if not digits:
        raise ValueError("Gronsfeld key must contain numeric digits")
    out = []
    j = 0
    for ch in text:
        if ch.isalpha():
            shift = digits[j % len(digits)]
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base + shift) % 26 + base))
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def gronsfeld_decrypt(text: str, key: str | list[int] | int) -> str:
    """Decrypt text using Gronsfeld cipher (Vigenere with numeric digit keys)."""
    digits = [int(d) for d in str(key) if d.isdigit()]
    if not digits:
        raise ValueError("Gronsfeld key must contain numeric digits")
    out = []
    j = 0
    for ch in text:
        if ch.isalpha():
            shift = digits[j % len(digits)]
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base - shift) % 26 + base))
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def base64url_decode(s: str) -> bytes:
    """Decode RFC 4648 Section 5 URL-safe base64 string with automatic padding."""
    import base64
    clean = s.strip()
    padded = clean + "=" * ((4 - len(clean) % 4) % 4)
    return base64.urlsafe_b64decode(padded)


BASE45_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
BASE45_MAP = {c: i for i, c in enumerate(BASE45_CHARSET)}


def base45_encode(data: bytes | str) -> str:
    """Encode bytes or string into RFC 9285 Base45 format."""
    if isinstance(data, str):
        raw = data.encode("utf-8")
    else:
        raw = bytes(data)

    res = []
    i = 0
    while i < len(raw):
        if i + 1 < len(raw):
            val = (raw[i] << 8) + raw[i + 1]
            c0 = BASE45_CHARSET[val % 45]
            c1 = BASE45_CHARSET[(val // 45) % 45]
            c2 = BASE45_CHARSET[(val // (45 * 45)) % 45]
            res.extend([c0, c1, c2])
            i += 2
        else:
            val = raw[i]
            c0 = BASE45_CHARSET[val % 45]
            c1 = BASE45_CHARSET[(val // 45) % 45]
            res.extend([c0, c1])
            i += 1
    return "".join(res)


def base45_decode(s: str) -> bytes:
    """Decode RFC 9285 Base45 string into raw bytes."""
    clean = s.strip()
    res = bytearray()
    i = 0
    while i < len(clean):
        if i + 2 < len(clean):
            c0, c1, c2 = clean[i], clean[i + 1], clean[i + 2]
            val = BASE45_MAP[c0] + BASE45_MAP[c1] * 45 + BASE45_MAP[c2] * 45 * 45
            res.append(val // 256)
            res.append(val % 256)
            i += 3
        elif i + 1 < len(clean):
            c0, c1 = clean[i], clean[i + 1]
            val = BASE45_MAP[c0] + BASE45_MAP[c1] * 45
            res.append(val)
            i += 2
        else:
            raise ValueError("Invalid Base45 string length")
    return bytes(res)


BASE58_CHARSET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_MAP = {c: i for i, c in enumerate(BASE58_CHARSET)}


def base58_encode(data: bytes | str) -> str:
    """Encode bytes or string into Bitcoin Base58 format."""
    if isinstance(data, str):
        raw = data.encode("utf-8")
    else:
        raw = bytes(data)

    if not raw:
        return ""

    leading_zeros = 0
    for b in raw:
        if b == 0:
            leading_zeros += 1
        else:
            break

    val = int.from_bytes(raw, byteorder="big")
    res = []
    while val > 0:
        res.append(BASE58_CHARSET[val % 58])
        val //= 58
    res.reverse()

    return (BASE58_CHARSET[0] * leading_zeros) + "".join(res)


def base58_decode(s: str) -> bytes:
    """Decode Bitcoin Base58 string into raw bytes."""
    clean = s.strip()
    if not clean:
        return b""

    leading_ones = 0
    for c in clean:
        if c == BASE58_CHARSET[0]:
            leading_ones += 1
        else:
            break

    val = 0
    for c in clean:
        if c not in BASE58_MAP:
            raise ValueError(f"Invalid Base58 character: {c}")
        val = val * 58 + BASE58_MAP[c]

    res = []
    while val > 0:
        res.append(val % 256)
        val //= 256
    res.reverse()

    return (b"\x00" * leading_ones) + bytes(res)


def bacon_decode(cipher: str, a_char: str = "A", b_char: str = "B") -> str:
    """Decode Bacon cipher where 5-bit binary tokens map to letters a-z."""
    clean = [c for c in cipher.upper() if c in (a_char.upper(), b_char.upper())]
    out = []
    for i in range(0, len(clean), 5):
        chunk = clean[i : i + 5]
        if len(chunk) == 5:
            val = 0
            for ch in chunk:
                val = (val << 1) | (1 if ch == b_char.upper() else 0)
            if 0 <= val < 26:
                out.append(chr(ord("a") + val))
            else:
                out.append("?")
    return "".join(out)


def bacon_encode(text: str, a_char: str = "A", b_char: str = "B") -> str:
    """Encode text into Bacon cipher 5-bit binary tokens."""
    out = []
    for ch in text.lower():
        if "a" <= ch <= "z":
            val = ord(ch) - ord("a")
            bits = []
            for shift in range(4, -1, -1):
                bits.append(b_char if (val >> shift) & 1 else a_char)
            out.append("".join(bits))
    return " ".join(out)


def scytale_encrypt(plaintext: str, diameter: int, pad: str = "x") -> str:
    """Encrypt a message using Scytale transposition cipher with given cylinder diameter (circumference)."""
    if diameter <= 0:
        raise ValueError("Diameter must be positive")
    n = len(plaintext)
    if n == 0:
        return ""
    cols = (n + diameter - 1) // diameter
    padded = plaintext.ljust(diameter * cols, pad)
    grid = [[""] * cols for _ in range(diameter)]
    for c in range(cols):
        for r in range(diameter):
            grid[r][c] = padded[c * diameter + r]
    return "".join("".join(row) for row in grid)


def scytale_decrypt(ciphertext: str, diameter: int, strip_pad: bool = False, pad: str = "x") -> str:
    """Decrypt a Scytale transposition cipher given cylinder diameter (number of rows)."""
    if diameter <= 0:
        raise ValueError("Diameter must be positive")
    n = len(ciphertext)
    if n == 0:
        return ""
    cols = (n + diameter - 1) // diameter
    padded = ciphertext.ljust(diameter * cols, pad)
    out: list[str] = []
    for c in range(cols):
        for r in range(diameter):
            out.append(padded[r * cols + c])
    res = "".join(out)[:n]
    if strip_pad:
        res = res.rstrip(pad)
    return res


TAP_GRID: list[list[str]] = [
    ["A", "B", "C", "D", "E"],
    ["F", "G", "H", "I", "J"],
    ["L", "M", "N", "O", "P"],
    ["Q", "R", "S", "T", "U"],
    ["V", "W", "X", "Y", "Z"],
]


def tap_code_encode(text: str, delimiter: str = " ") -> str:
    """
    Encode text using the Tap Code (Knock Code) 5x5 Polybius grid.
    'K' is mapped to 'C' (1.3).
    Returns coordinates formatted as 'row.col' separated by delimiter.
    """
    char_map: dict[str, tuple[int, int]] = {}
    for r_idx, row in enumerate(TAP_GRID, start=1):
        for c_idx, ch in enumerate(row, start=1):
            char_map[ch] = (r_idx, c_idx)
    char_map["K"] = (1, 3)

    tokens: list[str] = []
    for ch in text.upper():
        if ch in char_map:
            r, c = char_map[ch]
            tokens.append(f"{r}.{c}")
        elif ch.isspace():
            continue
    return delimiter.join(tokens)


def tap_code_decode(cipher: str) -> str:
    """
    Decode Tap Code (Knock Code) into lowercase text.
    Handles:
      - Coordinate pairs: '4.4 1.1 3.5' or '44 11 35'
      - Dot notation: '.... . / . . / ... .....'
      - Space-separated digits: '4 4 1 1 3 5'
    """
    import re

    clean = cipher.strip()
    if not clean:
        return ""

    if re.fullmatch(r"[\.\s/|]+", clean) and not any(ch.isdigit() for ch in clean):
        tokens = [t for t in re.split(r"\s+", clean) if t and t not in "/|"]
        coords: list[tuple[int, int]] = []
        i = 0
        while i < len(tokens):
            if i + 1 < len(tokens):
                r = tokens[i].count(".")
                c = tokens[i + 1].count(".")
                coords.append((r, c))
                i += 2
            else:
                break
    else:
        raw_digits = re.findall(r"[1-5]", clean)
        coords = []
        for i in range(0, len(raw_digits) - 1, 2):
            coords.append((int(raw_digits[i]), int(raw_digits[i + 1])))

    out: list[str] = []
    for r, c in coords:
        if 1 <= r <= 5 and 1 <= c <= 5:
            out.append(TAP_GRID[r - 1][c - 1])
        else:
            out.append("?")
    return "".join(out).lower()

def rot47(text: str) -> str:
    """
    Perform ROT-47 symmetric cipher on ASCII printable characters (range 33 '!' to 126 '~').
    The transformation is an involution: rot47(rot47(x)) == x.
    """
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if 33 <= code <= 126:
            out.append(chr(33 + ((code - 33 + 47) % 94)))
        else:
            out.append(ch)
    return "".join(out)

NATO_ALPHABET: dict[str, str] = {
    "A": "Alpha",
    "B": "Bravo",
    "C": "Charlie",
    "D": "Delta",
    "E": "Echo",
    "F": "Foxtrot",
    "G": "Golf",
    "H": "Hotel",
    "I": "India",
    "J": "Juliett",
    "K": "Kilo",
    "L": "Lima",
    "M": "Mike",
    "N": "November",
    "O": "Oscar",
    "P": "Papa",
    "Q": "Quebec",
    "R": "Romeo",
    "S": "Sierra",
    "T": "Tango",
    "U": "Uniform",
    "V": "Victor",
    "W": "Whiskey",
    "X": "X-ray",
    "Y": "Yankee",
    "Z": "Zulu",
}


def nato_phonetic_encode(text: str, delimiter: str = " ") -> str:
    """
    Encode text into the ICAO/NATO phonetic spelling alphabet tokens.
    """
    tokens: list[str] = []
    for ch in text.upper():
        if ch in NATO_ALPHABET:
            tokens.append(NATO_ALPHABET[ch])
        elif ch.isspace():
            continue
    return delimiter.join(tokens)


def nato_phonetic_decode(text: str) -> str:
    """
    Decode ICAO/NATO phonetic alphabet words back into characters.
    """
    import re

    words = re.findall(r"[A-Za-z]+", text)
    nato_upper = {v.upper(): k for k, v in NATO_ALPHABET.items()}
    nato_upper["XRAY"] = "X"

    chars: list[str] = []
    for w in words:
        wu = w.upper()
        if wu in nato_upper:
            chars.append(nato_upper[wu])
        elif len(w) == 1 and w.isalpha():
            chars.append(w.upper())
    return "".join(chars).lower()

def trithemius_encrypt(text: str, step: int = 1) -> str:
    """
    Encrypt text using Johannes Trithemius progressive Caesar cipher (Polygraphia, 1518).
    Each alphabetical character's Caesar shift increases by `step` per letter.
    """
    out: list[str] = []
    shift = 0
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
            shift += step
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
            shift += step
        else:
            out.append(ch)
    return "".join(out)


def trithemius_decrypt(text: str, step: int = 1) -> str:
    """
    Decrypt text encrypted with Trithemius progressive Caesar cipher.
    """
    out: list[str] = []
    shift = 0
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") - shift) % 26 + ord("a")))
            shift += step
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") - shift) % 26 + ord("A")))
            shift += step
        else:
            out.append(ch)
    return "".join(out)

def multiplicative_encrypt(text: str, a: int, modulus: int = 26) -> str:
    """
    Encrypt text using a modular multiplicative cipher: E(x) = (a * x) mod m.
    Requires gcd(a, m) == 1.
    """
    if gcd(a, modulus) != 1:
        raise ValueError(f"Multiplier a ({a}) must be coprime with modulus ({modulus})")

    out: list[str] = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            x = ord(ch) - base
            out.append(chr((a * x) % modulus + base))
        else:
            out.append(ch)
    return "".join(out)


def multiplicative_decrypt(text: str, a: int, modulus: int = 26) -> str:
    """
    Decrypt text using a modular multiplicative cipher: D(y) = (a^-1 * y) mod m.
    Requires gcd(a, m) == 1.
    """
    if gcd(a, modulus) != 1:
        raise ValueError(f"Multiplier a ({a}) must be coprime with modulus ({modulus})")
    a_inv = modinv(a, modulus)

    out: list[str] = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            y = ord(ch) - base
            out.append(chr((a_inv * y) % modulus + base))
        else:
            out.append(ch)
    return "".join(out)

def rot18(text: str) -> str:
    """
    Apply ROT18 cipher (ROT13 on alphabetic characters + ROT5 on numeric digits 0-9).
    This operation is an involution (applying it twice recovers the original plaintext).
    """
    out: list[str] = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + 13) % 26 + ord("A")))
        elif "0" <= ch <= "9":
            out.append(chr((ord(ch) - ord("0") + 5) % 10 + ord("0")))
        else:
            out.append(ch)
    return "".join(out)

T9_KEYPAD: dict[str, str] = {
    "2": "abc",
    "3": "def",
    "4": "ghi",
    "5": "jkl",
    "6": "mno",
    "7": "pqrs",
    "8": "tuv",
    "9": "wxyz",
    "0": " ",
}


def t9_decode(sequence: str) -> str:
    """
    Decode ITU-T E.161 mobile phone multi-tap sequence into text.
    Tokens are typically space-separated.
    Example: '8 33 999 66 444 66 33 8 33 99 8' -> 'teyninetext'
    """
    tokens = sequence.strip().split()
    out: list[str] = []
    for token in tokens:
        if not token:
            continue
        first = token[0]
        if first in T9_KEYPAD:
            letters = T9_KEYPAD[first]
            count = len(token)
            out.append(letters[(count - 1) % len(letters)])
        else:
            out.append(token)
    return "".join(out)



def bin_to_gray(n: int) -> int:
    """Convert binary integer to Gray code."""
    return n ^ (n >> 1)


def gray_to_bin(g: int) -> int:
    """Convert Gray code integer to binary integer."""
    b = 0
    while g > 0:
        b ^= g
        g >>= 1
    return b


def gray_encode_bytes(data: bytes) -> bytes:
    """Encode each byte using Gray code."""
    return bytes(bin_to_gray(b) & 0xFF for b in data)


def gray_decode_bytes(data: bytes) -> bytes:
    """Decode each byte from Gray code to standard binary."""
    return bytes(gray_to_bin(b) & 0xFF for b in data)


def repeating_key_xor(data: bytes, key: bytes) -> bytes:
    """XOR data bytes with a repeating key bytes."""
    if not key:
        raise ValueError("Key cannot be empty")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def beaufort_encrypt(plaintext: str, key: str) -> str:
    """Encrypt using the Beaufort cipher (reciprocal): C = (K - P) % 26."""
    return beaufort_decrypt(plaintext, key)


def beaufort_decrypt(ciphertext: str, key: str) -> str:
    """Decrypt using the Beaufort cipher (reciprocal): P = (K - C) % 26."""
    out: list[str] = []
    key = key.upper()
    k_idx = 0
    for ch in ciphertext:
        if "a" <= ch <= "z":
            k = ord(key[k_idx % len(key)]) - ord("A")
            c = ord(ch) - ord("a")
            p = (k - c) % 26
            out.append(chr(p + ord("a")))
            k_idx += 1
        elif "A" <= ch <= "Z":
            k = ord(key[k_idx % len(key)]) - ord("A")
            c = ord(ch) - ord("A")
            p = (k - c) % 26
            out.append(chr(p + ord("A")))
            k_idx += 1
        else:
            out.append(ch)
    return "".join(out)


def autokey_encrypt(plaintext: str, primer: str) -> str:
    """Encrypt using Vigenère autokey cipher (key = primer + plaintext)."""
    out: list[str] = []
    key_stream: list[str] = list(primer.lower())
    k_idx = 0
    for ch in plaintext:
        if "a" <= ch <= "z":
            k = ord(key_stream[k_idx]) - ord("a")
            c = (ord(ch) - ord("a") + k) % 26
            out.append(chr(c + ord("a")))
            key_stream.append(ch)
            k_idx += 1
        elif "A" <= ch <= "Z":
            k = ord(key_stream[k_idx]) - ord("a")
            c = (ord(ch) - ord("A") + k) % 26
            out.append(chr(c + ord("A")))
            key_stream.append(ch.lower())
            k_idx += 1
        else:
            out.append(ch)
    return "".join(out)


def autokey_decrypt(ciphertext: str, primer: str) -> str:
    """Decrypt using Vigenère autokey cipher (key = primer + plaintext)."""
    out: list[str] = []
    key_stream: list[str] = list(primer.lower())
    k_idx = 0
    for ch in ciphertext:
        if "a" <= ch <= "z":
            k = ord(key_stream[k_idx]) - ord("a")
            p = (ord(ch) - ord("a") - k) % 26
            pch = chr(p + ord("a"))
            out.append(pch)
            key_stream.append(pch)
            k_idx += 1
        elif "A" <= ch <= "Z":
            k = ord(key_stream[k_idx]) - ord("a")
            p = (ord(ch) - ord("A") - k) % 26
            pch = chr(p + ord("A"))
            out.append(pch)
            key_stream.append(pch.lower())
            k_idx += 1
        else:
            out.append(ch)
    return "".join(out)


def porta_decrypt(ciphertext: str, key: str) -> str:
    """Decrypt Porta polyalphabetic reciprocal cipher."""
    key = key.upper()
    pt: list[str] = []
    k_idx = 0
    for char in ciphertext:
        if "A" <= char.upper() <= "Z":
            is_lower = char.islower()
            k = key[k_idx % len(key)]
            k_idx += 1
            shift = (ord(k) - ord("A")) // 2
            c_val = ord(char.upper()) - ord("A")
            if c_val < 13:
                p_val = 13 + (c_val + shift) % 13
            else:
                p_val = (c_val - 13 - shift) % 13
            dec_char = chr(ord("A") + p_val)
            pt.append(dec_char.lower() if is_lower else dec_char)
        else:
            pt.append(char)
    return "".join(pt)


def columnar_transposition_decrypt(ciphertext: str, key: str, padding_char: str = "x") -> str:
    """Decrypt keyed columnar transposition cipher."""
    num_cols = len(key)
    num_rows = len(ciphertext) // num_cols
    order = sorted(range(num_cols), key=lambda i: key[i])
    cols: dict[int, str] = {}
    for idx, col_idx in enumerate(order):
        cols[col_idx] = ciphertext[idx * num_rows : (idx + 1) * num_rows]
    pt: list[str] = []
    for r in range(num_rows):
        for c in range(num_cols):
            pt.append(cols[c][r])
    return "".join(pt).rstrip(padding_char)


def rail_fence_decrypt(ciphertext: str, rails: int = 4) -> str:
    """Decrypt Rail Fence transposition cipher."""
    from collections import Counter
    length = len(ciphertext)
    pattern: list[int] = []
    rail = 0
    direction = 1
    for _ in range(length):
        pattern.append(rail)
        rail += direction
        if rail == rails - 1:
            direction = -1
        elif rail == 0:
            direction = 1
    counts = Counter(pattern)
    slices: dict[int, list[str]] = {}
    curr = 0
    for r in range(rails):
        slices[r] = list(ciphertext[curr : curr + counts[r]])
        curr += counts[r]
    return "".join(slices[r].pop(0) for r in pattern)


def qwerty_shift_decrypt(ciphertext: str, steps: int = -1) -> str:
    """Decrypt keyboard layout shift cipher (QWERTY rows)."""
    rows = ("qwertyuiop", "asdfghjkl", "zxcvbnm")
    out: list[str] = []
    for c in ciphertext:
        is_lower = c.islower()
        ch_low = c.lower()
        shifted = c
        for r in rows:
            if ch_low in r:
                idx = r.index(ch_low)
                new_ch = r[(idx + steps) % len(r)]
                shifted = new_ch if is_lower else new_ch.upper()
                break
        out.append(shifted)
    return "".join(out)


def book_cipher_decode(ciphertext: str, book_text: str) -> str:
    """Decode book cipher with coordinate references '[word_idx].[letter_idx]'."""
    book = book_text.split()
    tokens = ciphertext.replace(",", " ").split()
    out: list[str] = []
    for tok in tokens:
        if "." in tok:
            w_idx, l_idx = tok.split(".", 1)
            w = int(w_idx) - 1
            l = int(l_idx) - 1
            if 0 <= w < len(book) and 0 <= l < len(book[w]):
                out.append(book[w][l])
    return "".join(out)


def variant_beaufort_decrypt(ciphertext: str, key: str) -> str:
    """Decrypt Variant Beaufort cipher (C = P - K => P = C + K mod 26)."""
    key = key.lower()
    pt: list[str] = []
    for i, c in enumerate(ciphertext):
        if "a" <= c <= "z":
            k_val = ord(key[i % len(key)]) - ord("a")
            c_val = ord(c) - ord("a")
            pt.append(chr(ord("a") + (c_val + k_val) % 26))
        elif "A" <= c <= "Z":
            k_val = ord(key[i % len(key)]) - ord("a")
            c_val = ord(c) - ord("A")
            pt.append(chr(ord("A") + (c_val + k_val) % 26))
        else:
            pt.append(c)
    return "".join(pt)
