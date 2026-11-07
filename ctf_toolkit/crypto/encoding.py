from __future__ import annotations

import base64
import codecs
import re


BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def base62_encode(data: bytes | int) -> str:
    """
    Encode bytes or integer using Base62 (GMP / standard alphanumeric).
    Preserves leading zero bytes.
    """
    if isinstance(data, int):
        num = data
        leading_zeros = 0
    else:
        raw_bytes = bytes(data)
        if not raw_bytes:
            return ""
        leading_zeros = 0
        for b in raw_bytes:
            if b == 0:
                leading_zeros += 1
            else:
                break
        num = int.from_bytes(raw_bytes, "big")

    if num == 0:
        return BASE62_ALPHABET[0] * (leading_zeros if leading_zeros > 0 else 1)

    res: list[str] = []
    while num > 0:
        num, rem = divmod(num, 62)
        res.append(BASE62_ALPHABET[rem])

    return (BASE62_ALPHABET[0] * leading_zeros) + "".join(reversed(res))


def base62_decode(s: str) -> bytes:
    """
    Decode a Base62 string into raw bytes.
    Preserves leading zeros.
    """
    clean = s.strip()
    if not clean:
        return b""

    leading_zeros = 0
    for ch in clean:
        if ch == BASE62_ALPHABET[0]:
            leading_zeros += 1
        else:
            break

    num = 0
    for ch in clean:
        idx = BASE62_ALPHABET.find(ch)
        if idx == -1:
            raise ValueError(f"Invalid Base62 character: {ch!r}")
        num = num * 62 + idx

    if num == 0:
        return b"\x00" * leading_zeros

    byte_len = (num.bit_length() + 7) // 8
    raw = num.to_bytes(byte_len, "big")
    return (b"\x00" * leading_zeros) + raw


def decode_hexdump(dump_str: str) -> bytes:
    """
    Extract raw bytes from formatted hexdump text (xxd, Wireshark, space-separated, etc.).
    Strips line headers, offsets, and ASCII sidebars.
    """
    lines = dump_str.strip().splitlines()
    hex_chunks: list[str] = []
    for line in lines:
        cleaned_line = line.strip()
        if not cleaned_line:
            continue
        if "|" in cleaned_line:
            parts = cleaned_line.split("|")
            cleaned_line = parts[0].strip()
        cleaned_line = re.sub(r"^(?:0x)?[0-9a-fA-F]+:\s*", "", cleaned_line)
        cleaned_line = re.sub(r"^[0-9a-fA-F]{4,8}\s{2,}", "", cleaned_line)
        parts = re.split(r"\s{2,}", cleaned_line)
        hex_part = parts[0]
        raw_tokens = re.findall(r"[0-9a-fA-F]{2}", hex_part)
        if raw_tokens:
            hex_chunks.extend(raw_tokens)

    return bytes.fromhex("".join(hex_chunks))

def base32_decode_autopad(text: str) -> bytes:
    """Decode Base32 string with automatic padding calculation and whitespace stripping."""
    clean = re.sub(r"[^A-Za-z2-7=]", "", text.strip())
    unpadded = clean.rstrip("=")
    pad_len = (8 - (len(unpadded) % 8)) % 8
    padded = unpadded + ("=" * pad_len)
    return base64.b32decode(padded.encode("ascii"), casefold=True)


def quoted_printable_decode(data: str | bytes) -> bytes:
    """
    Decode Quoted-Printable (RFC 2045) encoded data.
    Commonly encountered in MIME emails, vCards, and legacy transfer formats.
    """
    import quopri

    raw = data.encode("utf-8") if isinstance(data, str) else data
    return quopri.decodestring(raw)


def rot13(text: str) -> str:
    """Perform ROT-13 symmetric substitution."""
    return codecs.decode(text, "rot_13")


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


def binary_to_text(binary_str: str) -> str:
    """Convert space-separated or continuous 8-bit binary representation into ASCII string."""
    clean = re.sub(r"[^01\s]", "", binary_str.strip())
    tokens = clean.split()
    if not tokens or len(tokens) == 1:
        s = clean.replace(" ", "")
        tokens = [s[i : i + 8] for i in range(0, len(s), 8) if len(s[i : i + 8]) == 8]
    return "".join([chr(int(b, 2)) for b in tokens if len(b) >= 7])


def decimal_to_text(decimal_str: str) -> str:
    """Convert space/comma-separated decimal ASCII character codes into string."""
    numbers = [int(n) for n in re.findall(r"\b\d+\b", decimal_str)]
    return "".join([chr(n) for n in numbers if 0 <= n <= 1114111])


def ascii85_decode(data: str | bytes) -> bytes:
    """Decode Adobe Ascii85 encoded string or bytes."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return base64.a85decode(raw.strip())


def base85_decode(data: str | bytes) -> bytes:
    """Decode RFC 1924 / IPv6 style Base85 encoded string or bytes."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return base64.b85decode(raw.strip())


def smart_decode(text: str) -> dict[str, str]:
    """Attempt multiple standard encodings on a string and return successful decodes."""
    results: dict[str, str] = {}
    clean = text.strip()

    # Binary
    if re.fullmatch(r"([01]{7,8}\s*)+", clean):
        try:
            results["binary"] = binary_to_text(clean)
        except Exception:
            pass

    # Decimal codes
    if re.fullmatch(r"(\d{1,3}[\s,]+)+\d{1,3}", clean):
        try:
            results["decimal"] = decimal_to_text(clean)
        except Exception:
            pass

    # A1Z26 Positional numbers
    if re.fullmatch(r"(\d{1,2}[-\s,]+)+\d{1,2}", clean) and not re.search(r"[a-zA-Z]", clean):
        try:
            from ctf_toolkit.crypto.classical import a1z26_decode
            results["a1z26"] = a1z26_decode(clean)
        except Exception:
            pass

    # Hex
    try:
        hex_cand = clean[2:] if clean.startswith("0x") else clean
        hex_bytes = bytes.fromhex(hex_cand)
        results["hex"] = hex_bytes.decode("utf-8", errors="replace")
    except Exception:
        pass

    # Base64
    try:
        b64_pad = clean + ("=" * ((4 - len(clean) % 4) % 4))
        b64_bytes = base64.b64decode(b64_pad)
        if any(32 <= b <= 126 for b in b64_bytes):
            results["base64"] = b64_bytes.decode("utf-8", errors="replace")
    except Exception:
        pass

    # Base32
    try:
        b32_bytes = base32_decode_autopad(clean)
        if any(32 <= b <= 126 for b in b32_bytes):
            results["base32"] = b32_bytes.decode("utf-8", errors="replace")
    except Exception:
        pass

    # Base62
    if re.fullmatch(r"[0-9A-Za-z]+", clean) and len(clean) >= 8:
        try:
            b62_bytes = base62_decode(clean)
            if any(32 <= b <= 126 for b in b62_bytes):
                results["base62"] = b62_bytes.decode("utf-8", errors="replace")
        except Exception:
            pass

    # Ascii85
    try:
        a85_bytes = ascii85_decode(clean)
        if any(32 <= b <= 126 for b in a85_bytes):
            results["ascii85"] = a85_bytes.decode("utf-8", errors="replace")
    except Exception:
        pass

    # ROT13
    r13 = rot13(clean)
    if r13 != clean:
        results["rot13"] = r13

    # ROT47
    r47 = rot47(clean)
    if r47 != clean and ("GETSFLAG" in r47 or "FLAG" in r47 or any(c.isalpha() for c in r47)):
        results["rot47"] = r47

    # Quoted-Printable
    if "=3D" in clean or re.search(r"=[0-9A-Fa-f]{2}", clean):
        try:
            qp_bytes = quoted_printable_decode(clean)
            results["quoted_printable"] = qp_bytes.decode("utf-8", errors="replace")
        except Exception:
            pass

    return results

import re
import html


def decode_html_entities(text: str) -> str:
    """
    Decode HTML numeric character references (&#NN; and &#xHH;) and standard HTML entities.
    """
    return html.unescape(text)



def rle_decode(text: str) -> str:
    """Decode Run-Length Encoded (RLE) string like '1G1E1T1S...'."""
    import re
    matches = re.findall(r"(\d+)(.)", text)
    return "".join(ch * int(count) for count, ch in matches)


def rle_encode(text: str) -> str:
    """Encode string to Run-Length Encoded (RLE) format."""
    if not text:
        return ""
    out: list[str] = []
    count = 1
    for i in range(1, len(text)):
        if text[i] == text[i - 1]:
            count += 1
        else:
            out.append(f"{count}{text[i - 1]}")
            count = 1
    out.append(f"{count}{text[-1]}")
    return "".join(out)


def normalize_fullwidth(text: str) -> str:
    """Normalize fullwidth Unicode characters to standard ASCII."""
    import unicodedata
    return unicodedata.normalize("NFKC", text)
