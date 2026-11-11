from __future__ import annotations

import re
from typing import Any
from ctf_toolkit.crypto.auto_decode import auto_decode_layers
from ctf_toolkit.crypto.rsa import rsa_solve_pqec, rsa_solve_phi_e_c
from ctf_toolkit.crypto.rsa_auto import solve_rsa_auto


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


def solve_challenge_text(desc: str) -> str | None:
    """Automated multi-heuristic analyzer for CTF challenge text/prompts."""
    # 1. Direct flag presence
    flag = extract_flag(desc)
    if flag:
        return flag

    # 2. Check for RSA parameters in text: p, q, e, c or n, phi, e, c
    p_m = re.search(r"\bp\s*=\s*(\d+)", desc)
    q_m = re.search(r"\bq\s*=\s*(\d+)", desc)
    e_m = re.search(r"\be\s*=\s*(\d+)", desc)
    c_m = re.search(r"\bc\s*=\s*(\d+)", desc)
    n_m = re.search(r"\bn\s*=\s*(\d+)", desc)
    phi_m = re.search(r"\b(?:phi|\u03c6)\s*=\s*(\d+)", desc, re.IGNORECASE)

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

    # 3. Code block extraction / cipher text
    code_blocks = re.findall(r"```(?:\w+)?\n?(.*?)```", desc, re.DOTALL)
    for block in code_blocks:
        cand_flag = extract_flag(block)
        if cand_flag:
            return cand_flag
        # Peel multi-layer encodings
        peeled = auto_decode_layers(block.strip())
        cand = extract_flag(peeled)
        if cand:
            return cand

    # 4. Full-text auto decode peeling
    peeled_full = auto_decode_layers(desc.strip())
    cand = extract_flag(peeled_full)
    if cand:
        return cand

    return None
