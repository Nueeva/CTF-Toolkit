from __future__ import annotations

import base64
import binascii
import re
from ctf_toolkit.crypto.encoding import smart_decode


def auto_decode_layers(data: bytes | str, max_layers: int = 8) -> bytes:
    """
    Peel nested encoding layers (Hex, Base64, Base32, Base85, ASCII85, URL, ROT13)
    automatically until a flag pattern or terminal plaintext is reached.
    """
    curr = data.encode("utf-8") if isinstance(data, str) else bytes(data)

    for _ in range(max_layers):
        text = curr.decode("utf-8", errors="ignore").strip()
        if not text:
            break
        if re.search(r"(?:TECHCOMFEST\d*|COMPFEST\d*|GEMASTIK\d*|WRECKIT\d*|HOLOGY\d*|SLASHROOT\d*|GETSFLAG|CTFLEARN|picoCTF|SEKAI|HIDC\d*|ARA\d*|CHTB|HTB|THM|ASIS|DICE|HOPE|OOO|ARKAV|LACTF|ACTF|LKS|CTF|FLAG|CT)\{[^}]+\}", text, re.IGNORECASE):
            return curr

        next_val: bytes | None = None
        # 0. Check Morse code
        if next_val is None and re.fullmatch(r"[.\- /_\n]+", text) and (".-" in text or "-." in text or "..." in text or "---" in text):
            try:
                from ctf_toolkit.crypto.morse import morse_decode
                cand_m = morse_decode(text)
                if cand_m and len(cand_m) >= 4 and "?" not in cand_m:
                    next_val = cand_m.encode("utf-8")
            except Exception:
                next_val = None

        # 0.1 Check A1Z26 / Number sequence (e.g. 3-20-6-1-12-19)
        if next_val is None and re.fullmatch(r"(?:\d{1,2}[ -/,\.]?)+", text) and any(sep in text for sep in ("-", " ", ",")):
            try:
                from ctf_toolkit.crypto.classical import a1z26_decode
                cand_a = a1z26_decode(text)
                if cand_a and len(cand_a) >= 4 and "?" not in cand_a and any(c in cand_a.lower() for c in "aeiou"):
                    next_val = cand_a.encode("utf-8")
            except Exception:
                next_val = None

        # 1. Try Hex
        if len(text) >= 4 and len(text) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", text):
            try:
                next_val = binascii.unhexlify(text)
            except Exception:
                next_val = None

        # 2. Try Base85 / ASCII85 (<~ ... ~>)
        if next_val is None and text.startswith("<~") and text.endswith("~>"):
            try:
                next_val = base64.a85decode(text.encode("ascii"), adobe=True)
            except Exception:
                next_val = None

        # 3. Try Base32
        if next_val is None and len(text) >= 8 and re.fullmatch(r"[A-Z2-7=]+", text):
            try:
                padded = text + "=" * ((8 - len(text) % 8) % 8)
                next_val = base64.b32decode(padded)
            except Exception:
                next_val = None

        # 4. Try Base64 / Base64URL
        if next_val is None and len(text) >= 4 and re.fullmatch(r"[A-Za-z0-9+/=\-_]+", text):
            try:
                padded = text + "=" * ((4 - len(text) % 4) % 4)
                cand = base64.urlsafe_b64decode(padded)
                if cand and sum(1 for b in cand if 32 <= b <= 126 or b in (9, 10, 13)) >= len(cand) * 0.75:
                    next_val = cand
            except Exception:
                next_val = None

        # 5. Check all 25 Caesar / ROT shifts & ROT47 for flag pattern
        flag_patt = r"(?:TECHCOMFEST\d*|COMPFEST\d*|GEMASTIK\d*|WRECKIT\d*|HOLOGY\d*|SLASHROOT\d*|GETSFLAG|CTFLEARN|picoCTF|SEKAI|HIDC\d*|ARA\d*|CHTB|HTB|THM|ASIS|DICE|HOPE|OOO|ARKAV|LACTF|ACTF|LKS|CTF|FLAG|CT)\{[^}]+\}"
        if any(c.isalpha() for c in text):
            for shift in range(1, 26):
                shifted = []
                for ch in text:
                    if 'a' <= ch <= 'z':
                        shifted.append(chr((ord(ch) - 97 - shift) % 26 + 97))
                    elif 'A' <= ch <= 'Z':
                        shifted.append(chr((ord(ch) - 65 - shift) % 26 + 65))
                    else:
                        shifted.append(ch)
                cand_caesar = "".join(shifted)
                if re.search(flag_patt, cand_caesar, re.IGNORECASE):
                    return cand_caesar.encode("utf-8")

        # 5.1 ROT47
        rot47_chars = []
        for ch in text:
            o = ord(ch)
            if 33 <= o <= 126:
                rot47_chars.append(chr(33 + ((o - 33 + 47) % 94)))
            else:
                rot47_chars.append(ch)
        rot47_str = "".join(rot47_chars)
        if re.search(flag_patt, rot47_str, re.IGNORECASE):
            return rot47_str.encode("utf-8")

        # 6. Fallback to smart_decode
        if next_val is None:
            try:
                sd = smart_decode(text)
                if isinstance(sd, str) and sd != text and "\ufffd" not in sd:
                    next_val = sd.encode("utf-8")
            except Exception:
                next_val = None

        if next_val is None or next_val == curr:
            break
        curr = next_val

    return curr
