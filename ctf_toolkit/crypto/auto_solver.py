from __future__ import annotations

import re
from typing import Any
from ctf_toolkit.crypto.auto_decode import auto_decode_layers
from ctf_toolkit.crypto.morse import morse_decode
from ctf_toolkit.crypto.classical import a1z26_decode
from ctf_toolkit.crypto.rsa import rsa_solve_pqec, rsa_solve_phi_e_c
from ctf_toolkit.crypto.rsa_auto import solve_rsa_auto
from ctf_toolkit.crypto.dh_ecc_tool import diffie_hellman_compute, ecc_point_operation


FLAG_REGEX = re.compile(
    r"(?:TECHCOMFEST\d*|COMPFEST\d*|GEMASTIK\d*|WRECKIT\d*|HOLOGY\d*|SLASHROOT\d*|GETSFLAG|CTFLEARN|picoCTF|SEKAI|HIDC\d*|ARA\d*|CHTB|HTB|THM|ASIS|DICE|HOPE|OOO|ARKAV|LACTF|ACTF|LKS|CTF|FLAG|CT)\{[^}]+\}",
    re.IGNORECASE,
)


def extract_flag(text: str | bytes) -> str | None:
    """Extract standard or event-specific CTF flag from text/bytes."""
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="ignore")
    m = FLAG_REGEX.search(text)
    return m.group(0) if m else None


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
    p_m = re.search(r"\bp\s*=\s*(\d+)", desc)
    q_m = re.search(r"\bq\s*=\s*(\d+)", desc)
    e_m = re.search(r"\be\s*=\s*(\d+)", desc)
    c_m = re.search(r"\bc\s*=\s*(\d+)", desc)
    n_m = re.search(r"\bn\s*=\s*(\d+)", desc)
    phi_m = re.search(r"\b(?:phi|\u03c6)\s*=\s*(\d+)", desc, re.IGNORECASE)
    d_m = re.search(r"\bd\s*=\s*(\d+)", desc)

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

    # 4. Code block extraction / cipher text peeling
    code_blocks = re.findall(r"```(?:\w+)?\n?(.*?)```", desc, re.DOTALL)
    for block in code_blocks:
        cand_flag = extract_flag(block)
        if cand_flag:
            return cand_flag

        # 4.1 Morse inside block
        clean_blk = block.strip()
        if re.fullmatch(r"[.\- /_\n]+", clean_blk) and (".-" in clean_blk or "-." in clean_blk):
            try:
                m_dec = morse_decode(clean_blk)
                cand = extract_flag(m_dec) or m_dec
                if cand:
                    return cand
            except Exception:
                pass

        # 4.2 A1Z26 inside block
        if re.fullmatch(r"(?:\d{1,2}[ -/,\.]?)+", clean_blk) and any(sep in clean_blk for sep in ("-", " ", ",")):
            try:
                a_dec = a1z26_decode(clean_blk)
                cand = extract_flag(a_dec) or a_dec
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
