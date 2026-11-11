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

        # 5. Check ROT13 / Caesar if flag pattern emerges
        import codecs
        rot = codecs.decode(text, "rot_13")
        if re.search(r"(?:TECHCOMFEST\d*|COMPFEST\d*|GEMASTIK\d*|WRECKIT\d*|HOLOGY\d*|SLASHROOT\d*|GETSFLAG|CTFLEARN|picoCTF|SEKAI|HIDC\d*|ARA\d*|CHTB|HTB|THM|ASIS|DICE|HOPE|OOO|ARKAV|LACTF|ACTF|LKS|CTF|FLAG|CT)\{[^}]+\}", rot, re.IGNORECASE):
            return rot.encode("utf-8")

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
