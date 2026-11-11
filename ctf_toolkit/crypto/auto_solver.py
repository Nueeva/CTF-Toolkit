from __future__ import annotations

import binascii
import re
from typing import Any
from ctf_toolkit.crypto.auto_decode import auto_decode_layers
from ctf_toolkit.crypto.morse import morse_decode
from ctf_toolkit.crypto.classical import a1z26_decode
from ctf_toolkit.crypto.rsa import rsa_solve_pqec, rsa_solve_phi_e_c
from ctf_toolkit.crypto.rsa_auto import solve_rsa_auto
from ctf_toolkit.crypto.dh_ecc_tool import diffie_hellman_compute, ecc_point_operation
from ctf_toolkit.utils.flag_manager import get_flag_manager


def extract_flag(text: str | bytes) -> str | None:
    """Extract standard or event-specific CTF flag via intelligent dynamic flag manager."""
    res = get_flag_manager().find_first_flag(text)
    if res and any(ph in res.lower() for ph in ("{hasil}", "{...}", "{flag}", "{string}", "{isi}")):
        return None
    return res


def solve_crypto_task(desc: str) -> str | None:
    """
    State-of-the-art multi-paradigm crypto solver:
    - Direct Flag Hunter
    - Textbook RSA (p, q, e, c)
    - RSA with leaked phi (n, phi, e, c)
    - RSA with leaked private exponent (n, d, c)
    - Automated RSA factor / attack (small n, Wiener, Fermat, Hastad)
    - Diffie-Hellman Shared Secret (p, g, A, B, a, b)
    - Elliptic Curve point multiplication / addition
    - Morse Code extraction
    - A1Z26 / Letter Position decoding
    - Multi-layer auto peeling (Hex, B64, B32, B85, ROT, XOR)
    """
    # 1. Direct flag presence
    flag = extract_flag(desc)
    if flag:
        return flag

    # 2. RSA: Check explicit parameters
    p_m = re.search(r"(?:\b|^)p\s*=\s*(\d+)", desc, re.MULTILINE)
    q_m = re.search(r"(?:\b|^)q\s*=\s*(\d+)", desc, re.MULTILINE)
    r_m = re.search(r"(?:\b|^)r\s*=\s*(\d+)", desc, re.MULTILINE)
    e_m = re.search(r"(?:\b|^)e\d*\s*=\s*(\d+)", desc, re.MULTILINE)
    c_m = re.search(r"(?:\b|^)c\d*\s*=\s*(?:\([^)]*\)\s*=\s*)?(\d+)", desc, re.MULTILINE)
    n_m = re.search(r"(?:\b|^)n\d*\s*=\s*(\d+)", desc, re.MULTILINE)
    phi_m = re.search(r"(?:\b|^)(?:phi|φ)\s*=\s*(\d+)", desc, re.IGNORECASE | re.MULTILINE)
    d_m = re.search(r"(?:\b|^)d\s*=\s*(\d+)", desc, re.MULTILINE)

    # 2.0.1 Multi-modulus attacks: Common Modulus (n, c1, e1, c2, e2) & Hastad Broadcast (n1..nk, c1..ck) & Shared Prime gcd(n1, n2)
    n_all = re.findall(r"(?:^|[^\w])n\d*\s*=\s*(\d+)", desc, re.MULTILINE)
    e_all = re.findall(r"(?:^|[^\w])e\d*\s*=\s*(\d+)", desc, re.MULTILINE)
    c_all = re.findall(r"(?:^|[^\w])c\d*\s*=\s*(\d+)", desc, re.MULTILINE)

    # 2.0.1a Common Modulus Attack (1 modulus n, two exponents e1, e2, two ciphertexts c1, c2)
    if len(e_all) >= 2 and len(c_all) >= 2 and n_m:
        from ctf_toolkit.crypto.rsa import common_modulus_attack
        try:
            n_val = int(n_m.group(1))
            c1, c2 = int(c_all[0]), int(c_all[1])
            e1, e2 = int(e_all[0]), int(e_all[1])
            m_cm = common_modulus_attack(c1, e1, c2, e2, n_val)
            pt_bytes = m_cm.to_bytes((m_cm.bit_length() + 7) // 8, "big")
            cand = extract_flag(pt_bytes) or pt_bytes.decode("utf-8", errors="ignore").strip()
            if cand:
                return cand
        except Exception:
            pass

    # 2.0.1b Hastad Broadcast (same small e, k distinct moduli n1..nk and c1..ck where k >= e)
    if len(n_all) >= 3 and len(c_all) >= 3:
        from ctf_toolkit.crypto.rsa import hastad_broadcast
        try:
            e_val = int(e_m.group(1)) if e_m else 3
            n_list = [int(x) for x in n_all]
            c_list = [int(x) for x in c_all]
            m_hastad = hastad_broadcast(c_list, n_list, e_val)
            pt_bytes = m_hastad.to_bytes((m_hastad.bit_length() + 7) // 8, "big")
            cand = extract_flag(pt_bytes) or pt_bytes.decode("utf-8", errors="ignore").strip()
            if cand:
                return cand
        except Exception:
            pass

    # 2.0.1c Shared Prime gcd(n1, n2)
    if len(n_all) >= 2 and c_m:
        from math import gcd
        try:
            n1, n2 = int(n_all[0]), int(n_all[1])
            common_p = gcd(n1, n2)
            if 1 < common_p < n1:
                q1 = n1 // common_p
                e_val = int(e_m.group(1)) if e_m else 65537
                c_val = int(c_m.group(1))
                pt = rsa_solve_pqec(common_p, q1, e_val, c_val)
                cand = extract_flag(pt) or pt.decode("utf-8", errors="ignore").strip()
                if cand:
                    return cand
        except Exception:
            pass

    # 2.0.2 RSA Modulus Kuadrat: n = p^2 => phi = p*(p-1)
    if "p²" in desc or "p^2" in desc or "modulus kuadrat" in desc.lower():
        if n_m and e_m and c_m:
            from ctf_toolkit.utils.math import integer_nthroot
            try:
                n_val, e_val, c_val = int(n_m.group(1)), int(e_m.group(1)), int(c_m.group(1))
                p_cand, is_square = integer_nthroot(n_val, 2)
                if is_square:
                    phi_kuadrat = p_cand * (p_cand - 1)
                    pt = rsa_solve_phi_e_c(n_val, phi_kuadrat, e_val, c_val)
                    cand = extract_flag(pt) or pt.decode("utf-8", errors="ignore").strip()
                    if cand:
                        return cand
            except Exception:
                pass

    # 2.0.3 RSA-CRT Complete (p, q, dp, dq, qinv)
    dp_m = re.search(r"\bdp\s*=\s*(\d+)", desc)
    dq_m = re.search(r"\bdq\s*=\s*(\d+)", desc)
    qinv_m = re.search(r"\bqinv\s*=\s*(\d+)", desc)
    if p_m and q_m and dp_m and dq_m and qinv_m and c_m:
        from ctf_toolkit.crypto.rsa import rsa_crt_reconstruct
        try:
            p_val = int(p_m.group(1))
            q_val = int(q_m.group(1))
            dp_val = int(dp_m.group(1))
            dq_val = int(dq_m.group(1))
            qinv_val = int(qinv_m.group(1))
            c_val = int(c_m.group(1))
            m_crt = rsa_crt_reconstruct(c_val, p_val, q_val, dp_val, dq_val, qinv_val)
            pt_bytes = m_crt.to_bytes((m_crt.bit_length() + 7) // 8, "big")
            cand = extract_flag(pt_bytes) or pt_bytes.decode("utf-8", errors="ignore").strip()
            if cand:
                return cand
        except Exception:
            pass

    # 2.0 Multi-prime RSA (p, q, r, ...)
    if p_m and q_m and r_m and e_m and c_m:
        from ctf_toolkit.crypto.rsa import rsa_multiprime_decrypt
        try:
            factors = [int(p_m.group(1)), int(q_m.group(1)), int(r_m.group(1))]
            # check if there are more primes like s, t
            s_m = re.search(r"\bs\s*=\s*(\d+)", desc)
            if s_m:
                factors.append(int(s_m.group(1)))
            e_val, c_val = int(e_m.group(1)), int(c_m.group(1))
            m_val = rsa_multiprime_decrypt(factors, e_val, c_val)
            pt_bytes = m_val.to_bytes((m_val.bit_length() + 7) // 8, "big")
            cand = extract_flag(pt_bytes) or pt_bytes.decode("utf-8", errors="ignore").strip()
            if cand:
                return cand
        except Exception:
            pass

    if p_m and q_m and e_m and c_m:
        p, q, e, c = int(p_m.group(1)), int(q_m.group(1)), int(e_m.group(1)), int(c_m.group(1))
        try:
            pt = rsa_solve_pqec(p, q, e, c)
            cand = extract_flag(pt) or pt.decode("utf-8", errors="ignore").strip()
            if cand:
                return cand
        except Exception:
            pass

    if n_m and phi_m and e_m and c_m:
        n, phi, e, c = int(n_m.group(1)), int(phi_m.group(1)), int(e_m.group(1)), int(c_m.group(1))
        try:
            pt = rsa_solve_phi_e_c(n, phi, e, c)
            cand = extract_flag(pt) or pt.decode("utf-8", errors="ignore").strip()
            if cand:
                return cand
        except Exception:
            pass

    if n_m and d_m and c_m:
        n, d, c = int(n_m.group(1)), int(d_m.group(1)), int(c_m.group(1))
        try:
            m = pow(c, d, n)
            pt_bytes = m.to_bytes((m.bit_length() + 7) // 8, "big")
            cand = extract_flag(pt_bytes) or pt_bytes.decode("utf-8", errors="ignore").strip()
            if cand:
                return cand
        except Exception:
            pass

    if n_m and e_m and c_m:
        n, e, c = int(n_m.group(1)), int(e_m.group(1)), int(c_m.group(1))
        try:
            res = solve_rsa_auto(n=n, e=e, c=c)
            if res and isinstance(res, dict) and "plaintext" in res:
                cand = extract_flag(res["plaintext"]) or res["plaintext"]
                if cand:
                    return str(cand)
        except Exception:
            pass

    # 3. Diffie-Hellman Key Exchange parameters
    g_m = re.search(r"\bg\s*=\s*(\d+)", desc)
    A_m = re.search(r"\bA\s*=\s*(\d+)", desc)
    B_m = re.search(r"\bB\s*=\s*(\d+)", desc)
    a_m = re.search(r"\ba\s*=\s*(\d+)", desc)
    b_m = re.search(r"\bb\s*=\s*(\d+)", desc)

    if p_m and g_m and (A_m or B_m or a_m or b_m):
        try:
            dh_res = diffie_hellman_compute(
                p=int(p_m.group(1)),
                g=int(g_m.group(1)),
                A=int(A_m.group(1)) if A_m else None,
                B=int(B_m.group(1)) if B_m else None,
                a=int(a_m.group(1)) if a_m else None,
                b=int(b_m.group(1)) if b_m else None,
            )
            s = dh_res.get("shared_secret")
            if s is not None and isinstance(s, int):
                # Try decoding shared secret as flag
                try:
                    s_bytes = s.to_bytes((s.bit_length() + 7) // 8, "big")
                    cand = extract_flag(s_bytes)
                    if cand:
                        return cand
                except Exception:
                    pass
        except Exception:
            pass

    # 3.1 Scytale detection in text / code block
    scytale_m = re.search(r"scytale.*?diameter.*?(\d+)", desc, re.IGNORECASE)
    ct_m = re.search(r"(?:ciphertext|ct):\s*([a-zA-Z0-9_]+)", desc, re.IGNORECASE)
    if scytale_m and ct_m:
        try:
            from ctf_toolkit.crypto.classical import scytale_decrypt
            diam = int(scytale_m.group(1))
            ct_text = ct_m.group(1).strip()
            dec_scytale = scytale_decrypt(ct_text, diam)
            cand = extract_flag(dec_scytale)
            if not cand:
                # Wrap as GETSFLAG{hasil} if prompted by challenge
                dec_clean = dec_scytale.rstrip("x")
                cand = f"GETSFLAG{{{dec_clean}}}"
            if cand:
                return cand
        except Exception:
            pass

    # 3.2 Trithemius detection (huruf ke-i digeser +i)
    if "trithemius" in desc.lower():
        ct_tri = ct_m.group(1).strip() if ct_m else None
        if not ct_tri:
            # try finding ciphertext in block
            code_blk = re.search(r"```[^\n]*\n(?:ciphertext:\s*)?([a-zA-Z]+)", desc)
            if code_blk:
                ct_tri = code_blk.group(1).strip()
        if ct_tri:
            try:
                from ctf_toolkit.crypto.classical import trithemius_decrypt
                dec_tri = trithemius_decrypt(ct_tri)
                cand = extract_flag(dec_tri) or f"GETSFLAG{{{dec_tri}}}"
                if cand:
                    return cand
            except Exception:
                pass

    # 3.3 Explicit Repeating-Key XOR / 1-Byte XOR with known key
    hex_ct_m = re.search(r"(?:ct\(hex\)|ciphertext\(hex\)|hex)=\s*([0-9a-fA-F]+)", desc, re.IGNORECASE)
    if not hex_ct_m:
        hex_ct_m = re.search(r"(?:ct\(hex\)|ciphertext\(hex\)|hex):\s*([0-9a-fA-F]+)", desc, re.IGNORECASE)
    key_ascii_m = re.search(r"key\(ascii\)=\s*([^\n\r`]+)", desc, re.IGNORECASE)
    if not key_ascii_m:
        key_ascii_m = re.search(r"key\(ascii\):\s*([^\n\r`]+)", desc, re.IGNORECASE)
    xor_1byte_m = re.search(r"(?:kunci|key)\s*(?:1-byte)?\s*=\s*0x([0-9a-fA-F]{1,2})", desc, re.IGNORECASE)

    if hex_ct_m:
        raw_ct = binascii.unhexlify(hex_ct_m.group(1).strip())
        if key_ascii_m:
            try:
                from ctf_toolkit.crypto.classical import repeating_key_xor
                k_b = key_ascii_m.group(1).strip().encode("utf-8")
                dec_xor = repeating_key_xor(raw_ct, k_b).decode("utf-8", errors="ignore")
                cand = extract_flag(dec_xor) or dec_xor
                if cand:
                    return cand
            except Exception:
                pass
        if xor_1byte_m:
            try:
                k_val = int(xor_1byte_m.group(1), 16)
                dec_xor1 = bytes(b ^ k_val for b in raw_ct).decode("utf-8", errors="ignore")
                cand = extract_flag(dec_xor1) or dec_xor1
                if cand:
                    return cand
            except Exception:
                pass

    # 3.4 SHA256 / MD5 with small wordlist declared inline
    hash_inline_m = re.search(r"(?:sha256|md5)=([0-9a-fA-F]{32,64})", desc, re.IGNORECASE)
    wordlist_inline_m = re.search(r"wordlist:\s*([^\n\r`]+)", desc, re.IGNORECASE)
    if hash_inline_m and wordlist_inline_m:
        try:
            from ctf_toolkit.crypto.hashes import crack_wordlist_hash
            h_val = hash_inline_m.group(1).strip()
            w_list = [w.strip() for w in wordlist_inline_m.group(1).split(",") if w.strip()]
            h_algo = "sha256" if len(h_val) == 64 else "md5"
            cracked = crack_wordlist_hash(h_val, w_list, algorithm=h_algo)
            if cracked:
                return f"GETSFLAG{{{cracked}}}"
        except Exception:
            pass

    # 4. Code block extraction / cipher text peeling
    code_blocks = re.findall(r"```(?:\w+)?\n?(.*?)```", desc, re.DOTALL)
    for block in code_blocks:
        cand_flag = extract_flag(block)
        if cand_flag:
            return cand_flag

        # 4.1 Morse inside block
        clean_blk = block.strip()
        if re.fullmatch(r"[.\- /_\n]+", clean_blk) and ("." in clean_blk and "-" in clean_blk):
            try:
                m_dec = morse_decode(clean_blk)
                m_norm = m_dec.replace("(", "{").replace(")", "}")
                if "{" in m_norm:
                    prefix, inner = m_norm.split("{", 1)
                    inner_content = inner.rstrip("}").strip().lower()
                    if prefix.strip().upper() == "CT":
                        cand = f"GETSFLAG{{{inner_content}}}"
                    else:
                        cand = f"{prefix.strip()}{{{inner_content}}}"
                else:
                    cand = extract_flag(m_dec) or m_dec
                if cand:
                    return cand
            except Exception:
                pass

        # 4.2 A1Z26 inside block
        if re.fullmatch(r"(?:\d{1,2}[ -/,\.]?)+", clean_blk) and any(sep in clean_blk for sep in ("-", " ", ",")):
            try:
                a_dec = a1z26_decode(clean_blk)
                cand = extract_flag(a_dec)
                if not cand:
                    clean_a = a_dec.lower()
                    if clean_a.startswith("ctf"):
                        cand = f"GETSFLAG{{{clean_a[3:]}}}"
                    elif clean_a.startswith("getsflag"):
                        cand = f"GETSFLAG{{{clean_a[8:]}}}"
                    else:
                        cand = f"GETSFLAG{{{clean_a}}}"
                if cand:
                    return cand
            except Exception:
                pass

        # 4.3 Multi-layer peel
        peeled = auto_decode_layers(clean_blk)
        cand = extract_flag(peeled)
        if cand:
            return cand

    # 5. Full text multi-layer peel
    peeled_full = auto_decode_layers(desc.strip())
    cand = extract_flag(peeled_full)
    if cand:
        return cand

    return None
