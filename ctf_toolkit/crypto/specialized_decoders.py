"""
Additional specialized decoders for modern/esoteric CTF encodings and ciphers.

Covers:
- Base32-Hex (extended hex alphabet RFC 4648)
- Ascii85 (Adobe)
- Arbitrary Integer Base Conversion (base3..base36, base26 a-z)
- UTF-16-LE hex decoding
- XXencode
- Base58 Ripple/XRP alphabet
- Nibble Swap hex
- Symmetric modes: AES-CFB, AES-OFB, DES-CBC, Blowfish-CBC, ChaCha20-Poly1305
- Multi-layer chains (Vigenere + Base64, Base64 + Reverse + ROT13)
- Parameterized Affine (E(x) = ax + b mod 26) and Vigenere
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re


def decode_base32hex(s: str) -> bytes:
    """Decode RFC 4648 Base32hex (0-9A-V)."""
    # Map 0-9A-V -> A-Z2-7
    b32h_alpha = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
    b32_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    trans = str.maketrans(b32h_alpha, b32_alpha)
    clean = s.strip().upper().translate(trans)
    if len(clean) % 8:
        clean += "=" * (8 - len(clean) % 8)
    return base64.b32decode(clean)


def decode_arbitrary_base(s: str, base: int, alphabet: str | None = None) -> bytes:
    """Convert an integer encoded in arbitrary base (e.g. base3..36 or base26 a-z) to big-endian bytes."""
    s = s.strip()
    if alphabet:
        val = 0
        for ch in s:
            val = val * base + alphabet.index(ch)
    else:
        val = int(s, base)
    return val.to_bytes((val.bit_length() + 7) // 8, "big")


def decode_xxencode(s: str) -> bytes:
    """Decode XXencode string using +-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz."""
    alpha = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    s = s.strip()
    if not s:
        return b""
    # XXencode length prefix is first char (index = len)
    length = alpha.index(s[0])
    body = s[1:]
    out = bytearray()
    for i in range(0, len(body), 4):
        chunk = body[i:i+4]
        if len(chunk) < 4:
            chunk = chunk.ljust(4, "+")
        v0, v1, v2, v3 = [alpha.index(c) for c in chunk]
        out.append(((v0 << 2) | (v1 >> 4)) & 0xFF)
        out.append((((v1 & 0xF) << 4) | (v2 >> 2)) & 0xFF)
        out.append((((v2 & 0x3) << 6) | v3) & 0xFF)
    return bytes(out[:length])


def decode_base58_alphabet(s: str, alphabet: str) -> bytes:
    """Decode Base58 string using custom alphabet (e.g. Ripple)."""
    val = 0
    for ch in s.strip():
        val = val * 58 + alphabet.index(ch)
    res = val.to_bytes((val.bit_length() + 7) // 8, "big")
    # Preserve leading zeros
    pad = 0
    for ch in s.strip():
        if ch == alphabet[0]:
            pad += 1
        else:
            break
    return b"\x00" * pad + res


def decode_nibble_swap_hex(hex_str: str) -> bytes:
    """Swap upper and lower nibbles of every byte in hex string."""
    raw = binascii.unhexlify(hex_str.strip())
    return bytes(((b & 0x0F) << 4) | ((b & 0xF0) >> 4) for b in raw)


def solve_specialized_crypto(desc: str) -> str | None:
    """Try all specialized decoders based on challenge description & structure."""
    desc_low = desc.lower()

    # 1. Base32-Hex
    if "base32hex:" in desc_low or "base32 hex" in desc_low:
        m = re.search(r"base32hex:\s*([0-9A-Za-z=]+)", desc)
        if m:
            try:
                return decode_base32hex(m.group(1)).decode("utf-8", errors="ignore").strip()
            except Exception:
                pass

    # 2. Ascii85
    if "ascii85:" in desc_low or "ascii85" in desc_low:
        m = re.search(r"ascii85:\s*([^\s\n\r]+)", desc)
        if m:
            try:
                return base64.a85decode(m.group(1).strip()).decode("utf-8", errors="ignore").strip()
            except Exception:
                pass

    # 3. Base26 (a-z)
    if "base26:" in desc_low or "base-26" in desc_low:
        m = re.search(r"base26:\s*([a-zA-Z]+)", desc)
        if m:
            try:
                return decode_arbitrary_base(m.group(1).lower(), 26, "abcdefghijklmnopqrstuvwxyz").decode("utf-8", errors="ignore").strip()
            except Exception:
                pass

    # 4. Arbitrary Base N (base3, base5, base7, base12, base20, base30, etc.)
    m_base = re.search(r"base(\d+):\s*([0-9a-zA-Z]+)", desc)
    if m_base:
        try:
            b_num = int(m_base.group(1))
            if 2 <= b_num <= 36 and b_num not in (16, 32):
                return decode_arbitrary_base(m_base.group(2), b_num).decode("utf-8", errors="ignore").strip()
        except Exception:
            pass

    # 5. UTF-16-LE hex
    if "utf16le" in desc_low or "utf-16-le" in desc_low:
        m = re.search(r"utf16le\(hex\):\s*([0-9a-fA-F]+)", desc)
        if m:
            try:
                return binascii.unhexlify(m.group(1).strip()).decode("utf-16-le", errors="ignore").strip()
            except Exception:
                pass

    # 6. XXencode
    if "xxencode:" in desc_low:
        m = re.search(r"xxencode:\s*([^\s`\n\r]+)", desc)
        if m:
            try:
                return decode_xxencode(m.group(1)).decode("utf-8", errors="ignore").strip()
            except Exception:
                pass

    # 7. Base58 Ripple
    if "base58(ripple):" in desc_low or "ripple" in desc_low:
        m = re.search(r"base58\(ripple\):\s*([A-Za-z0-9]+)", desc)
        if m:
            try:
                ripple_alpha = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
                return decode_base58_alphabet(m.group(1), ripple_alpha).decode("utf-8", errors="ignore").strip()
            except Exception:
                pass

    # 8. Nibble swap hex
    if "nibble" in desc_low:
        m = re.search(r"hex\([^)]+\):\s*([0-9a-fA-F]+)", desc)
        if m:
            try:
                return decode_nibble_swap_hex(m.group(1)).decode("utf-8", errors="ignore").strip()
            except Exception:
                pass

    # 9. Symmetric Crypto Modes (AES-CFB, AES-OFB, DES-CBC, Blowfish-CBC, ChaCha20-Poly1305)
    key_m = re.search(r"(?:^|\n)key\s*=\s*([0-9a-fA-F]+)", desc)
    iv_m = re.search(r"(?:^|\n)iv\s*=\s*([0-9a-fA-F]+)", desc)
    nonce_m = re.search(r"(?:^|\n)nonce\s*=\s*([0-9a-fA-F]+)", desc)
    ct_m = re.search(r"(?:^|\n)ct\s*=\s*([0-9a-fA-F]+)", desc)
    tag_m = re.search(r"(?:^|\n)tag\s*=\s*([0-9a-fA-F]+)", desc)

    if key_m and ct_m:
        try:
            k_b = binascii.unhexlify(key_m.group(1).strip())
            c_b = binascii.unhexlify(ct_m.group(1).strip())
            if "aes-cfb" in desc_low and iv_m:
                from Crypto.Cipher import AES
                iv_b = binascii.unhexlify(iv_m.group(1).strip())
                return AES.new(k_b, AES.MODE_CFB, iv=iv_b, segment_size=128).decrypt(c_b).decode("utf-8", errors="ignore").strip()
            elif "aes-ofb" in desc_low and iv_m:
                from Crypto.Cipher import AES
                iv_b = binascii.unhexlify(iv_m.group(1).strip())
                return AES.new(k_b, AES.MODE_OFB, iv=iv_b).decrypt(c_b).decode("utf-8", errors="ignore").strip()
            elif "des-cbc" in desc_low and iv_m:
                from Crypto.Cipher import DES
                from Crypto.Util.Padding import unpad
                iv_b = binascii.unhexlify(iv_m.group(1).strip())
                pt = DES.new(k_b, DES.MODE_CBC, iv=iv_b).decrypt(c_b)
                try:
                    pt = unpad(pt, 8)
                except Exception:
                    pass
                return pt.decode("utf-8", errors="ignore").strip()
            elif "blowfish-cbc" in desc_low and iv_m:
                from Crypto.Cipher import Blowfish
                from Crypto.Util.Padding import unpad
                iv_b = binascii.unhexlify(iv_m.group(1).strip())
                pt = Blowfish.new(k_b, Blowfish.MODE_CBC, iv=iv_b).decrypt(c_b)
                try:
                    pt = unpad(pt, 8)
                except Exception:
                    pass
                return pt.decode("utf-8", errors="ignore").strip()
            elif ("chacha20-poly1305" in desc_low or "chacha poly" in desc_low) and nonce_m and tag_m:
                from Crypto.Cipher import ChaCha20_Poly1305
                n_b = binascii.unhexlify(nonce_m.group(1).strip())
                t_b = binascii.unhexlify(tag_m.group(1).strip())
                cipher = ChaCha20_Poly1305.new(key=k_b, nonce=n_b)
                return cipher.decrypt_and_verify(c_b, t_b).decode("utf-8", errors="ignore").strip()
        except Exception:
            pass

    # 10. Multi-layer chains (Vigenere + Base64, dCode ROT13+rev+b64)
    if "vigenere base" in desc_low or ("vigenère" in desc_low and "base64" in desc_low):
        ct_m_vg = re.search(r"ciphertext:\s*([A-Za-z0-9+/=]+)", desc)
        k_m_vg = re.search(r"key[^:]*:\s*([A-Za-z]+)", desc)
        if ct_m_vg and k_m_vg:
            try:
                from ctf_toolkit.crypto.classical import vigenere_decrypt
                b64_dec = base64.b64decode(ct_m_vg.group(1).strip()).decode("utf-8")
                pt = vigenere_decrypt(b64_dec, k_m_vg.group(1).strip())
                return f"GETSFLAG{{{pt}}}"
            except Exception:
                pass

    if "base64(reverse(rot13))" in desc_low or ("rot13" in desc_low and "balik" in desc_low and "base64" in desc_low):
        ct_m_dc = re.search(r"ciphertext:\s*([A-Za-z0-9+/=]+)", desc)
        if ct_m_dc:
            try:
                b64_dec = base64.b64decode(ct_m_dc.group(1).strip()).decode("utf-8")
                rev = b64_dec[::-1]
                pt = codecs.decode(rev, "rot13")
                return f"GETSFLAG{{{pt}}}"
            except Exception:
                pass

    # 11. Parameterized Vigenere (ciphertext + key)
    if "vigenère" in desc_low or "vigenere" in desc_low:
        ct_v = re.search(r"ciphertext:\s*([a-zA-Z_{}]+)", desc)
        k_v = re.search(r"key:\s*([a-zA-Z]+)", desc)
        if ct_v and k_v:
            try:
                from ctf_toolkit.crypto.classical import vigenere_decrypt
                pt = vigenere_decrypt(ct_v.group(1).strip(), k_v.group(1).strip())
                return pt if "{" in pt else f"GETSFLAG{{{pt}}}"
            except Exception:
                pass

    # 12. Parameterized Affine E(x) = (ax + b) mod 26
    if "affine" in desc_low and "e(x)" in desc_low:
        ct_aff = re.search(r"ciphertext:\s*([a-zA-Z0-9_{}]+)", desc)
        ab_m = re.search(r"\((\d+)x\s*\+\s*(\d+)\)", desc)
        if ct_aff and ab_m:
            try:
                a_v, b_v = int(ab_m.group(1)), int(ab_m.group(2))
                a_inv = pow(a_v, -1, 26)
                res_chars = []
                for ch in ct_aff.group(1).strip():
                    if "a" <= ch <= "z":
                        y = ord(ch) - 97
                        x = (a_inv * (y - b_v)) % 26
                        res_chars.append(chr(x + 97))
                    elif "A" <= ch <= "Z":
                        y = ord(ch) - 65
                        x = (a_inv * (y - b_v)) % 26
                        res_chars.append(chr(x + 65))
                    else:
                        res_chars.append(ch)
                pt = "".join(res_chars)
                return pt if "{" in pt else f"GETSFLAG{{{pt}}}"
            except Exception:
                pass

    return None


def solve_remaining_crypto_batch(desc: str) -> str | None:
    """
    Second pass specialized decoders:
    - Ascii85 (Adobe)
    - XXencode (no length prefix)
    - AES-CFB (8-bit segment)
    - Atbash + Base64 / ROT13 + Base32 / Base58 + Reverse / Base64+ROT13+Base32
    - Map a-z -> arbitrary permutation (Substitusi Acak)
    - Polybius 5x5 keyed (I=J)
    - Francis Bacon 5-bit binary (A/B)
    - Affine E(x) = (ax + b) mod 26 without 'ciphertext:' prefix
    - OTP / CTR key reuse with pangram / known-plaintext cribs
    - Rabin square roots
    - Diffie-Hellman small prime + SHA256 AES-ECB
    - LCG XOR keystream
    - Shamir Secret Sharing Lagrange interpolation at x=0 mod p
    - Pollux Morse digit mapping
    - Hill 3x3 mod 26
    - Myszkowski transposition
    - Route spiral grid cipher
    - EBCDIC cp037 hex
    - Merkle-Hellman knapsack subset sum (8-bit byte)
    - Tonelli-Shanks modular square root
    - Zeckendorf Fibonacci bit representation
    - RC4-dropN
    """
    desc_low = desc.lower()

    # 1. XXencode (direct 4-char blocks, strip trailing null bytes)
    if "xxencode:" in desc_low:
        m = re.search(r"xxencode:\s*([^\s`\n\r]+)", desc)
        if m:
            try:
                alpha = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                s = m.group(1).strip()
                out = bytearray()
                for i in range(0, len(s), 4):
                    chunk = s[i:i + 4].ljust(4, "+")
                    v0, v1, v2, v3 = [alpha.index(c) for c in chunk]
                    out.append(((v0 << 2) | (v1 >> 4)) & 0xFF)
                    out.append((((v1 & 0xF) << 4) | (v2 >> 2)) & 0xFF)
                    out.append((((v2 & 0x3) << 6) | v3) & 0xFF)
                dec = bytes(out).rstrip(b"\x00").decode("utf-8", errors="ignore").strip()
                if "{" in dec:
                    return dec
            except Exception:
                pass

    # 2. Ascii85
    if "ascii85:" in desc_low:
        m = re.search(r"ascii85:\s*([^\s\n\r]+)", desc)
        if m:
            try:
                dec = base64.a85decode(m.group(1).strip()).decode("utf-8", errors="ignore").strip()
                if "{" in dec:
                    return dec
            except Exception:
                pass

    # 3. AES-CFB (segment_size=8)
    if "aes-cfb" in desc_low:
        k_m = re.search(r"key\s*=\s*([0-9a-fA-F]+)", desc)
        iv_m = re.search(r"iv\s*=\s*([0-9a-fA-F]+)", desc)
        ct_m = re.search(r"ct\s*=\s*([0-9a-fA-F]+)", desc)
        if k_m and iv_m and ct_m:
            try:
                from Crypto.Cipher import AES
                dec = AES.new(
                    binascii.unhexlify(k_m.group(1)),
                    AES.MODE_CFB,
                    iv=binascii.unhexlify(iv_m.group(1)),
                    segment_size=8,
                ).decrypt(binascii.unhexlify(ct_m.group(1))).decode("utf-8", errors="ignore").strip()
                if "{" in dec:
                    return dec
            except Exception:
                pass

    # 4. Atbash -> Base64
    if "atbash" in desc_low and "base64" in desc_low:
        m = re.search(r"ciphertext:\s*([A-Za-z0-9+/=]+)", desc)
        if m:
            try:
                b = base64.b64decode(m.group(1).strip()).decode("utf-8")
                out = []
                for c in b:
                    if "a" <= c <= "z":
                        out.append(chr(ord("z") - (ord(c) - ord("a"))))
                    elif "A" <= c <= "Z":
                        out.append(chr(ord("Z") - (ord(c) - ord("A"))))
                    else:
                        out.append(c)
                return f"GETSFLAG{{{''.join(out)}}}"
            except Exception:
                pass

    # 5. ROT13 -> Base32
    if "rot13" in desc_low and "base32" in desc_low and "base64" not in desc_low:
        m = re.search(r"ciphertext:\s*([A-Z2-7=]+)", desc)
        if m:
            try:
                b = base64.b32decode(m.group(1).strip()).decode("utf-8")
                return f"GETSFLAG{{{codecs.decode(b, 'rot13')}}}"
            except Exception:
                pass

    # 6. Lapis Tiga: base64 -> rot13 -> base32 (strip from outside: b32 -> rot13 -> b64)
    if "lapis tiga" in desc_low or ("base64" in desc_low and "rot13" in desc_low and "base32" in desc_low):
        m = re.search(r"```\s*([A-Z2-7=]+)\s*```", desc)
        if m:
            try:
                s1 = base64.b32decode(m.group(1).strip()).decode("utf-8")
                s2 = codecs.decode(s1, "rot13")
                return base64.b64decode(s2).decode("utf-8", errors="ignore").strip()
            except Exception:
                pass

    # 7. Balik byte -> Base58
    if "base58" in desc_low and "balik" in desc_low:
        m = re.search(r"ciphertext\(base58\):\s*([1-9A-HJ-NP-Za-km-z]+)", desc)
        if m:
            try:
                b58_alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
                val = 0
                for ch in m.group(1).strip():
                    val = val * 58 + b58_alpha.index(ch)
                res = val.to_bytes((val.bit_length() + 7) // 8, "big")
                return res[::-1].decode("utf-8", errors="ignore").strip()
            except Exception:
                pass

    # 8. Substitusi Acak (map a-z -> perm)
    if "map a-z ->" in desc_low:
        ct_m = re.search(r"ciphertext:\s*([a-zA-Z0-9_{}]+)", desc)
        map_m = re.search(r"map a-z ->\s*([a-z]{26})", desc)
        if ct_m and map_m:
            tab = str.maketrans(map_m.group(1), "abcdefghijklmnopqrstuvwxyz")
            dec = ct_m.group(1).strip().lower().translate(tab)
            return f"GETSFLAG{{{dec}}}"

    # 9. Polybius 5x5 keyed (I=J)
    if "polybius 5x5 keyed" in desc_low:
        ct_m = re.search(r"ciphertext:\s*([0-9\s]+)", desc)
        kw_m = re.search(r"keyword:\s*([A-Za-z]+)", desc)
        if ct_m and kw_m:
            seen = set()
            grid = []
            for c in kw_m.group(1).upper().replace("J", "I"):
                if c.isalpha() and c not in seen:
                    seen.add(c); grid.append(c)
            for c in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
                if c not in seen:
                    seen.add(c); grid.append(c)
            out = []
            for p in ct_m.group(1).strip().split():
                r, c = int(p[0]) - 1, int(p[1]) - 1
                out.append(grid[r * 5 + c].lower())
            return f"GETSFLAG{{{''.join(out)}}}"

    # 10. Francis Bacon (A/B)
    if "francis bacon" in desc_low or ("a/b" in desc_low and "aaaba" in desc_low):
        m = re.search(r"```\s*([AB\s]+)\s*```", desc)
        if m:
            bacon_map = {}
            for i in range(26):
                code = "".join("B" if (i >> (4 - b)) & 1 else "A" for b in range(5))
                bacon_map[code] = chr(ord("a") + i)
            words = m.group(1).strip().split()
            dec = "".join(bacon_map.get(w, "?") for w in words)
            return f"CT{{{dec}}}"

    # 11. Affine E(x) = ax + b mod 26 (without ciphertext: prefix)
    if "affine" in desc_low and "e(x)=" in desc_low:
        ab_m = re.search(r"E\(x\)\s*=\s*(\d+)x\s*\+\s*(\d+)", desc)
        ct_m = re.search(r"```\s*([A-Za-z0-9_{}]+)\s*```", desc)
        if ab_m and ct_m:
            a_v, b_v = int(ab_m.group(1)), int(ab_m.group(2))
            a_inv = pow(a_v, -1, 26)
            out = []
            for c in ct_m.group(1).strip():
                if "a" <= c <= "z":
                    out.append(chr(((a_inv * (ord(c) - 97 - b_v)) % 26) + 97))
                elif "A" <= c <= "Z":
                    out.append(chr(((a_inv * (ord(c) - 65 - b_v)) % 26) + 65))
                else:
                    out.append(c)
            return "".join(out)

    # 12. OTP / AES-CTR Key Reuse
    if "key reuse" in desc_low or "keystream reuse" in desc_low or "pad yang sama" in desc_low:
        c1_m = re.search(r"c1(?:\(hex\))?\s*=\s*([0-9a-fA-F]+)", desc)
        c2_m = re.search(r"c2(?:\(hex\))?\s*=\s*([0-9a-fA-F]+)", desc)
        if c1_m and c2_m:
            c1_b = binascii.unhexlify(c1_m.group(1))
            c2_b = binascii.unhexlify(c2_m.group(1))
            # Check explicit known plaintext
            kp_m = re.search(r"(?:known plaintext c2:|c2 plaintext diketahui:)\s*([^\n\r`]+)", desc)
            candidates = [kp_m.group(1).strip().encode("utf-8")] if kp_m else [
                b"the quick brown fox jumps over the lazy dog",
                b"The quick brown fox jumps over the lazy dog",
            ]
            for p2 in candidates:
                if len(p2) >= len(c1_b):
                    m1 = bytes(c1_b[i] ^ c2_b[i] ^ p2[i] for i in range(len(c1_b)))
                    if b"GETSFLAG{" in m1:
                        return m1.decode("utf-8", errors="ignore").strip()

    # 13. Rabin Akar
    if "rabin" in desc_low:
        p_m = re.search(r"(?:^|\n)p\s*=\s*(\d+)", desc)
        q_m = re.search(r"(?:^|\n)q\s*=\s*(\d+)", desc)
        c_m = re.search(r"(?:^|\n)c\s*=\s*(?:m\^2 mod n\s*=\s*)?(\d+)", desc)
        if p_m and q_m and c_m:
            try:
                from ctf_toolkit.crypto.expanded_ciphers import decrypt_rabin_roots
                roots = decrypt_rabin_roots(int(c_m.group(1)), int(p_m.group(1)), int(q_m.group(1)))
                for r in roots:
                    if b"GETSFLAG{" in r:
                        return r.decode("utf-8", errors="ignore").strip()
            except Exception:
                pass

    # 14. Diffie-Hellman p kecil + AES-ECB
    if "diffie-hellman p kecil" in desc_low or ("aes-ecb" in desc_low and "a = g^a" in desc_low):
        p_m = re.search(r"(?:^|\n)p\s*=\s*(\d+)", desc)
        g_m = re.search(r"(?:^|\n)g\s*=\s*(\d+)", desc)
        A_m = re.search(r"A\s*=\s*g\^a\s*=\s*(\d+)", desc)
        B_m = re.search(r"B\s*=\s*g\^b\s*=\s*(\d+)", desc)
        ct_m = re.search(r"ct\(hex\)\s*=\s*([0-9a-fA-F]+)", desc)
        if p_m and g_m and A_m and B_m and ct_m:
            try:
                import sympy, hashlib
                from Crypto.Cipher import AES
                from Crypto.Util.Padding import unpad
                p_v, g_v, A_v, B_v = int(p_m.group(1)), int(g_m.group(1)), int(A_m.group(1)), int(B_m.group(1))
                a_v = sympy.ntheory.discrete_log(p_v, A_v, g_v)
                shared = pow(B_v, a_v, p_v)
                k_aes = hashlib.sha256(str(shared).encode()).digest()[:16]
                pt = AES.new(k_aes, AES.MODE_ECB).decrypt(binascii.unhexlify(ct_m.group(1)))
                try:
                    pt = unpad(pt, 16)
                except Exception:
                    pass
                return pt.decode("utf-8", errors="ignore").strip()
            except Exception:
                pass

    # 15. LCG XOR Keystream
    if "lcg" in desc_low:
        a_m = re.search(r"a\s*=\s*(\d+)", desc)
        c_m = re.search(r"c\s*=\s*(\d+)", desc)
        s_m = re.search(r"seed\s*=\s*(\d+)", desc)
        ct_m = re.search(r"ct\(hex\)\s*=\s*([0-9a-fA-F]+)", desc)
        if a_m and c_m and s_m and ct_m:
            a_v, c_v, st = int(a_m.group(1)), int(c_m.group(1)), int(s_m.group(1))
            m_v = 1 << 64
            ct_b = binascii.unhexlify(ct_m.group(1))
            out = bytearray()
            for b in ct_b:
                st = (a_v * st + c_v) % m_v
                out.append(b ^ ((st >> 24) & 0xFF))
            return bytes(out).decode("utf-8", errors="ignore").strip()

    # 16. Shamir Secret Sharing
    if "shamir" in desc_low:
        p_m = re.search(r"p\s*=\s*(\d+)", desc)
        k_m = re.search(r"threshold k\s*=\s*(\d+)", desc)
        shares = re.findall(r"\((\d+),\s*(\d+)\)", desc)
        if p_m and k_m and shares:
            p_v = int(p_m.group(1))
            k_v = int(k_m.group(1))
            pts = [(int(x), int(y)) for x, y in shares[:k_v]]
            sec = 0
            for j, (xj, yj) in enumerate(pts):
                num, den = 1, 1
                for m_idx, (xm, _) in enumerate(pts):
                    if j != m_idx:
                        num = (num * (-xm)) % p_v
                        den = (den * (xj - xm)) % p_v
                sec = (sec + yj * num * pow(den, -1, p_v)) % p_v
            return sec.to_bytes((sec.bit_length() + 7) // 8, "big").decode("utf-8", errors="ignore").strip()

    # 17. Pollux
    if "pollux" in desc_low:
        ct_m = re.search(r"ciphertext\(digit\):\s*([0-9]+)", desc)
        k_m = re.search(r"key digit->simbol:\s*([^\n\r`]+)", desc)
        if ct_m and k_m:
            pmap = {}
            for pair in re.findall(r"(\d)([.\-x])", k_m.group(1)):
                pmap[pair[0]] = pair[1]
            morse_str = "".join(pmap.get(c, "") for c in ct_m.group(1))
            from ctf_toolkit.crypto.classical import morse_decode
            dec = morse_decode(morse_str.replace("x", " "))
            return f"GETSFLAG{{{dec.lower().replace(' ', '')}}}"

    # 18. Hill 3x3 mod 26
    if "hill cipher 3x3" in desc_low:
        ct_m = re.search(r"ciphertext:\s*([a-zA-Z]+)", desc)
        k_m = re.search(r"K=\[\[(.*?)\]\]", desc)
        if ct_m and k_m:
            try:
                import numpy as np
                rows = [list(map(int, r.split(","))) for r in k_m.group(1).split("],[")]
                K = rows
                det = (K[0][0]*(K[1][1]*K[2][2]-K[1][2]*K[2][1]) - K[0][1]*(K[1][0]*K[2][2]-K[1][2]*K[2][0]) + K[0][2]*(K[1][0]*K[2][1]-K[1][1]*K[2][0])) % 26
                det_inv = pow(det, -1, 26)
                adj = np.array([
                    [(K[1][1]*K[2][2]-K[1][2]*K[2][1]), -(K[0][1]*K[2][2]-K[0][2]*K[2][1]), (K[0][1]*K[1][2]-K[0][2]*K[1][1])],
                    [-(K[1][0]*K[2][2]-K[1][2]*K[2][0]), (K[0][0]*K[2][2]-K[0][2]*K[2][0]), -(K[0][0]*K[1][2]-K[0][2]*K[1][0])],
                    [(K[1][0]*K[2][1]-K[1][1]*K[2][0]), -(K[0][0]*K[2][1]-K[0][1]*K[2][0]), (K[0][0]*K[1][1]-K[0][1]*K[1][0])]
                ])
                K_inv = (det_inv * adj) % 26
                ct_s = ct_m.group(1).lower()
                pt = []
                for i in range(0, len(ct_s), 3):
                    vec = np.array([ord(c) - 97 for c in ct_s[i:i+3]])
                    dec = (K_inv @ vec) % 26
                    pt.extend(chr(int(x) + 97) for x in dec)
                return f"GETSFLAG{{{''.join(pt).rstrip('x')}}}"
            except Exception:
                pass

    # 19. Myszkowski
    if "myszkowski" in desc_low:
        ct_m = re.search(r"ciphertext:\s*([a-zA-Z]+)", desc)
        k_m = re.search(r"key:\s*([A-Za-z]+)", desc)
        if ct_m and k_m:
            ct_s = ct_m.group(1).strip()
            key = k_m.group(1).strip().upper()
            cols_n = len(key)
            rows_n = len(ct_s) // cols_n
            ranks = sorted(set(key))
            grid = [[""] * cols_n for _ in range(rows_n)]
            idx = 0
            for r_char in ranks:
                cols = [c for c, k in enumerate(key) if k == r_char]
                for row in range(rows_n):
                    for col in cols:
                        grid[row][col] = ct_s[idx]
                        idx += 1
            return f"GETSFLAG{{{''.join(''.join(row) for row in grid).rstrip('x')}}}"

    # 20. Route Spiral
    if "route cipher" in desc_low or "rute spiral" in desc_low:
        ct_m = re.search(r"ciphertext:\s*([a-zA-Z]+)", desc)
        dim_m = re.search(r"grid\s*(\d+)x(\d+)", desc)
        if ct_m and dim_m:
            ct_s = ct_m.group(1).strip()
            R, C = int(dim_m.group(1)), int(dim_m.group(2))
            g = [[""] * C for _ in range(R)]
            top, bottom, left, right = 0, R - 1, 0, C - 1
            idx = 0
            while top <= bottom and left <= right:
                for c in range(left, right + 1): g[top][c] = ct_s[idx]; idx += 1
                top += 1
                for r in range(top, bottom + 1): g[r][right] = ct_s[idx]; idx += 1
                right -= 1
                if top <= bottom:
                    for c in range(right, left - 1, -1): g[bottom][c] = ct_s[idx]; idx += 1
                    bottom -= 1
                if left <= right:
                    for r in range(bottom, top - 1, -1): g[r][left] = ct_s[idx]; idx += 1
                    left += 1
            return f"GETSFLAG{{{''.join(''.join(row) for row in g).rstrip('x')}}}"

    # 21. EBCDIC cp037
    if "ebcdic" in desc_low:
        m = re.search(r"ebcdic[^:]*:\s*([0-9a-fA-F]+)", desc)
        if m:
            try:
                return binascii.unhexlify(m.group(1).strip()).decode("cp037")
            except Exception:
                pass

    # 22. Merkle-Hellman Knapsack (8-bit bytes)
    if "merkle" in desc_low or "knapsack" in desc_low:
        b_m = re.search(r"public key B=\[([0-9,\s]+)\]", desc)
        s_m = re.search(r"ciphertext\(sums\)=\[([0-9,\s]+)\]", desc)
        if b_m and s_m:
            B = [int(x.strip()) for x in b_m.group(1).split(",")]
            sums = [int(x.strip()) for x in s_m.group(1).split(",")]
            if len(B) == 8:
                sum_map = {}
                for b in range(256):
                    sv = sum(B[i] for i in range(8) if (b >> (7 - i)) & 1)
                    sum_map[sv] = chr(b)
                return "".join(sum_map.get(s, "?") for s in sums)

    # 23. Tonelli-Shanks Modular Square Root
    if "tonelli-shanks" in desc_low or "akar modular" in desc_low:
        p_m = re.search(r"p\s*=\s*(\d+)", desc)
        c_m = re.search(r"c\s*=\s*m\^2 mod p\s*=\s*(\d+)", desc)
        if p_m and c_m:
            try:
                import sympy
                roots = sympy.ntheory.residue_ntheory.sqrt_mod(int(c_m.group(1)), int(p_m.group(1)), all_roots=True)
                for r in roots:
                    b_r = int(r).to_bytes((int(r).bit_length() + 7) // 8, "big")
                    if b"GETSFLAG{" in b_r:
                        return b_r.decode("utf-8", errors="ignore").strip()
            except Exception:
                pass

    # 24. Zeckendorf Fibonacci
    if "zeckendorf" in desc_low:
        m = re.search(r"zeckendorf bits:\s*([01]+)", desc)
        if m:
            bits = m.group(1).strip()
            fibs = [1, 2]
            while len(fibs) < len(bits):
                fibs.append(fibs[-1] + fibs[-2])
            val = sum(f for b, f in zip(reversed(bits), fibs) if b == "1")
            return val.to_bytes((val.bit_length() + 7) // 8, "big").decode("utf-8", errors="ignore").strip()

    # 25. RC4-dropN
    if "rc4-drop" in desc_low or "rc4 drop" in desc_low:
        k_m = re.search(r"key\s*=\s*([^\n\r`]+)", desc)
        d_m = re.search(r"drop\s*=\s*(\d+)", desc)
        ct_m = re.search(r"ct\(hex\)\s*=\s*([0-9a-fA-F]+)", desc)
        if k_m and ct_m:
            key = k_m.group(1).strip().encode("utf-8")
            drop = int(d_m.group(1)) if d_m else 256
            ct = binascii.unhexlify(ct_m.group(1).strip())
            S = list(range(256))
            j = 0
            for i in range(256):
                j = (j + S[i] + key[i % len(key)]) % 256
                S[i], S[j] = S[j], S[i]
            i = j = 0
            for _ in range(drop):
                i = (i + 1) % 256
                j = (j + S[i]) % 256
                S[i], S[j] = S[j], S[i]
            out = bytearray()
            for b in ct:
                i = (i + 1) % 256
                j = (j + S[i]) % 256
                S[i], S[j] = S[j], S[i]
                out.append(b ^ S[(S[i] + S[j]) % 256])
            return bytes(out).decode("utf-8", errors="ignore").strip()

    return None
