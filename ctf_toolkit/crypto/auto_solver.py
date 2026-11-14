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
from ctf_toolkit.crypto.candidate import accept_candidate, flag_prefixes
from ctf_toolkit.utils.flag_manager import get_flag_manager


def extract_flag(text: str | bytes) -> str | None:
    """Extract standard or event-specific CTF flag via intelligent dynamic flag manager."""
    res = get_flag_manager().find_first_flag(text)
    if res and any(ph in res.lower() for ph in ("{hasil}", "{...}", "{flag}", "{string}", "{isi}")):
        return None
    return res


def solve_crypto_task(desc: str) -> str | None:
    # 0.00 LKS & National Specific Solvers (Sum/Diff leak, Franklin-Reiter, CRT multi-cipher)
    desc_low = desc.lower()
    # LKSN: p + q and p - q leaks (e.g. p+q = ..., p-q = ...)
    if ("p+q" in desc_low or "p + q" in desc_low) and ("p-q" in desc_low or "p - q" in desc_low):
        r_m = re.search(r"(?:p\s*\+\s*q|r)\s*=\s*(\d+)", desc)
        s_m = re.search(r"(?:p\s*-\s*q|s)\s*=\s*(\d+)", desc)
        c_m_lks = re.search(r"(?:^|[^\w])c\s*=\s*(\d+)", desc)
        e_m_lks = re.search(r"(?:^|[^\w])e\s*=\s*(\d+)", desc)
        if r_m and s_m and c_m_lks:
            try:
                from ctf_toolkit.crypto.lks_national_suite import rsa_solve_sum_and_diff
                r_val = int(r_m.group(1))
                s_val = int(s_m.group(1))
                c_val = int(c_m_lks.group(1))
                e_val = int(e_m_lks.group(1)) if e_m_lks else 65537
                res_lks = rsa_solve_sum_and_diff(r_val, s_val, e_val, c_val)
                if res_lks:
                    cand = extract_flag(res_lks) or res_lks.decode("utf-8", errors="ignore").strip()
                    if cand:
                        return cand
            except Exception:
                pass

    # LKSN: Varian CRT Broadcast (N1..Nk, C1..Ck)
    n_indexed = re.findall(r"(?:^|[^\w])N\d*\s*=\s*(\d+)", desc)
    c_indexed = re.findall(r"(?:^|[^\w])C\d*\s*=\s*(\d+)", desc)
    if len(n_indexed) >= 3 and len(c_indexed) >= 3:
        try:
            from ctf_toolkit.crypto.lks_national_suite import rsa_hastad_broadcast_crt
            mods = [int(x) for x in n_indexed]
            cts = [int(x) for x in c_indexed]
            # Try e = 3, e = 7, e = 27
            for e_cand in (3, 7, 27):
                res_crt = rsa_hastad_broadcast_crt(mods, cts, e=e_cand)
                if res_crt:
                    cand = extract_flag(res_crt) or res_crt.decode("utf-8", errors="ignore").strip()
                    if cand:
                        return cand
        except Exception:
            pass

    # 0.0 Specialized Encodings & Modern Block/Stream Modes
    try:
        from ctf_toolkit.crypto.specialized_decoders import solve_specialized_crypto, solve_remaining_crypto_batch
        spec_sol = solve_remaining_crypto_batch(desc) or solve_specialized_crypto(desc)
        if spec_sol:
            return spec_sol
    except Exception:
        pass

    # 0. Early special pattern detectors
    desc_low = desc.lower()
    if "elgamal" in desc_low:
        p_m_eg = re.search(r"(?:^|\n)p\s*=\s*(\d+)", desc)
        c1_m_eg = re.search(r"(?:^|\n)c1\s*=\s*(\d+)", desc)
        c2_m_eg = re.search(r"(?:^|\n)c2\s*=\s*(\d+)", desc)
        x_m_eg = re.search(r"(?:^|\n)x(?:\s*\(privat\))?\s*=\s*(\d+)", desc)
        if p_m_eg and c1_m_eg and c2_m_eg and x_m_eg:
            try:
                p_v = int(p_m_eg.group(1))
                c1_v = int(c1_m_eg.group(1))
                c2_v = int(c2_m_eg.group(1))
                x_v = int(x_m_eg.group(1))
                s = pow(c1_v, x_v, p_v)
                s_inv = pow(s, -1, p_v)
                m = (c2_v * s_inv) % p_v
                pt_bytes = m.to_bytes((m.bit_length() + 7) // 8, "big")
                return extract_flag(pt_bytes) or pt_bytes.decode("utf-8", errors="ignore").strip()
            except Exception:
                pass
    if "xor satu byte" in desc_low or "byte rahasia" in desc_low:
        m_hex_xor = re.search(r"```\s*([0-9a-fA-F]{16,})\s*```", desc)
        if m_hex_xor:
            try:
                raw_hex = bytes.fromhex(m_hex_xor.group(1).strip())
                for k in range(256):
                    cand_x = bytes(b ^ k for b in raw_hex)
                    fl = extract_flag(cand_x)
                    if fl:
                        return fl
            except Exception:
                pass
    if ("terbalik base" in desc_low or "base64 yang dibalik" in desc_low) and "```" in desc:
        m_b64 = re.search(r"```\s*([A-Za-z0-9+/=]+)\s*```", desc)
        if m_b64:
            try:
                import base64
                return base64.b64decode(m_b64.group(1).strip()[::-1]).decode("latin-1")
            except Exception:
                pass

    if ("pagar rel" in desc_low or "rail fence" in desc_low or "zig-zag" in desc_low):
        m_rf = re.search(r"```\s*([A-Za-z0-9_{}]+)\s*```", desc)
        m_depth = re.search(r"(?:depth|rails?|rel)\s*=?\s*(\d+)", desc)
        if m_rf:
            try:
                from ctf_toolkit.crypto.classical import rail_fence_decrypt
                rails_k = int(m_depth.group(1)) if m_depth else 3
                ct_rf = m_rf.group(1).strip()
                cand_rf = rail_fence_decrypt(ct_rf, rails=rails_k)
                fl = extract_flag(cand_rf)
                if fl:
                    return fl
            except Exception:
                pass
    if "oktal" in desc_low or "octal" in desc_low or "basis 8" in desc_low:
        octs = re.findall(r"\b[0-7]{3}\b", desc)
        if len(octs) >= 5:
            try:
                dec_oct = bytes(int(x, 8) for x in octs).decode("utf-8", errors="ignore")
                if "{" in dec_oct and "}" in dec_oct:
                    return dec_oct.strip()
            except Exception:
                pass

    if "xor crib" in desc_low or "repeating-key xor" in desc_low or ("crib" in desc_low and ("repeating" in desc_low or "kunci berulang" in desc_low)):
        hex_m = re.search(r"ct\(hex\)\s*=\s*([0-9a-fA-F]+)", desc)
        if hex_m:
            try:
                ct_bytes = binascii.unhexlify(hex_m.group(1).strip())
                crib = flag_prefixes()[0].encode()
                keystream = bytes(ct_bytes[i] ^ crib[i] for i in range(len(crib)))
                for plen in range(1, len(keystream) + 1):
                    k_cand = keystream[:plen]
                    pt_cand = bytes(ct_bytes[i] ^ k_cand[i % plen] for i in range(len(ct_bytes)))
                    # Require full ASCII printable flag
                    try:
                        pt_str = pt_cand.decode("ascii")
                        if crib.decode() in pt_str and "}" in pt_str and all(32 <= ord(c) <= 126 for c in pt_str):
                            return pt_str.strip()
                    except UnicodeDecodeError:
                        pass
            except Exception:
                pass

    if "elgamal" in desc_low:
        p_m_eg = re.search(r"(?:^|\n)p\s*=\s*(\d+)", desc)
        c1_m_eg = re.search(r"(?:^|\n)c1\s*=\s*(\d+)", desc)
        c2_m_eg = re.search(r"(?:^|\n)c2\s*=\s*(\d+)", desc)
        x_m_eg = re.search(r"(?:^|\n)x(?:\s*\(privat\))?\s*=\s*(\d+)", desc)
        if p_m_eg and c1_m_eg and c2_m_eg and x_m_eg:
            try:
                from ctf_toolkit.crypto.expanded_ciphers import decrypt_elgamal
                p_v = int(p_m_eg.group(1))
                c1_v = int(c1_m_eg.group(1))
                c2_v = int(c2_m_eg.group(1))
                x_v = int(x_m_eg.group(1))
                pt_eg = decrypt_elgamal(c1_v, c2_v, p_v, x_v)
                return extract_flag(pt_eg) or pt_eg.decode("utf-8", errors="ignore").strip()
            except Exception:
                pass

    if "rc4" in desc_low:
        ct_m_rc4 = re.search(r"ct\(hex\)\s*=\s*([0-9a-fA-F]+)", desc)
        key_m_rc4 = re.search(r"key\s*=\s*([^\n\r`]+)", desc)
        if ct_m_rc4 and key_m_rc4:
            try:
                from ctf_toolkit.crypto import expanded_ciphers as ec
                c_b = binascii.unhexlify(ct_m_rc4.group(1).strip())
                k_b = key_m_rc4.group(1).strip().encode("utf-8")
                pt = ec.decrypt_rc4(c_b, k_b)
                if pt:
                    return extract_flag(pt) or pt.decode("utf-8", errors="ignore").strip()
            except Exception:
                pass

    if "aes kunci lemah" in desc_low or "1 byte diulang 16x" in desc_low:
        ct_m_w = re.search(r"ct\(hex\)\s*=\s*([0-9a-fA-F]+)", desc)
        if ct_m_w:
            try:
                from ctf_toolkit.crypto import expanded_ciphers as ec
                c_b = binascii.unhexlify(ct_m_w.group(1).strip())
                for b_val in range(256):
                    try:
                        pt = ec.decrypt_aes_ecb(c_b, bytes([b_val]) * 16)
                        fl = extract_flag(pt)
                        if fl:
                            return fl
                    except Exception:
                        pass
            except Exception:
                pass

    if "sandi buku" in desc_low or "book cipher" in desc_low:
        coords_m = re.search(r"ciphertext:\s*([0-9.\s]+)", desc)
        book_m = re.search(r"(?:^|\n)buku[^:]*:\s*([^\n\r`]+)", desc)
        if coords_m and book_m:
            try:
                b_words = book_m.group(1).strip().split()
                c_pairs = coords_m.group(1).strip().split()
                dec_bk = "".join(b_words[int(cd.split('.')[0])-1][int(cd.split('.')[1])-1] for cd in c_pairs)
                return accept_candidate(dec_bk)
            except Exception:
                pass

    # 1. Direct flag presence
    flag = extract_flag(desc)
    if flag:
        return flag

    # 1.5 Normalize parameter formatting (= / : / JSON / hex / indexed names)
    # into canonical "name = value" lines so the regex branches below fire
    # regardless of how the challenge text was written.
    try:
        from ctf_toolkit.crypto.param_parse import canonical_prelude
        _prelude = canonical_prelude(desc)
        if _prelude:
            desc = _prelude + desc
    except Exception:
        pass

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

        # 2.0.4 Coppersmith Stereotyped Message
        if e <= 5 and any(k in desc.lower() for k in ("known", "prefix", "flag", "getsflag{", "picoctf{")):
            try:
                from ctf_toolkit.crypto.coppersmith import coppersmith_stereotyped
                pref_match = re.search(r'(?:known|prefix|flag)\s*=\s*["\']?([a-zA-Z0-9_{]+)', desc, re.IGNORECASE)
                known_str = pref_match.group(1) if pref_match else "GETSFLAG{"
                if not any(known_str.startswith(k) for k in ("GETSFLAG{", "flag{", "picoCTF{", "LKS{")):
                    if "GETSFLAG{" in desc:
                        known_str = "GETSFLAG{"
                    elif "flag{" in desc:
                        known_str = "flag{"
                for unknown_len in (4, 5, 6, 7, 8, 9, 10):
                    shift = unknown_len * 8
                    known_int = int.from_bytes(known_str.encode(), "big") << shift
                    x_bound = 1 << shift
                    rec = coppersmith_stereotyped(n, e, c, known_int, x_bound, m=1)
                    if rec:
                        rec_bytes = int(rec).to_bytes((int(rec).bit_length() + 7) // 8, "big")
                        cand = extract_flag(rec_bytes)
                        if cand:
                            return cand
            except Exception:
                pass

    # 3. Diffie-Hellman Key Exchange parameters & Discrete Log
    g_m = re.search(r"\bg\s*=\s*(\d+)", desc)
    A_m = re.search(r"\bA\s*=\s*(\d+)", desc)
    B_m = re.search(r"\bB\s*=\s*(\d+)", desc)
    a_m = re.search(r"\ba\s*=\s*(\d+)", desc)
    b_m = re.search(r"\bb\s*=\s*(\d+)", desc)

    if p_m and g_m and (A_m or B_m or a_m or b_m):
        try:
            p_val = int(p_m.group(1))
            g_val = int(g_m.group(1))
            A_val = int(A_m.group(1)) if A_m else None
            B_val = int(B_m.group(1)) if B_m else None
            a_val = int(a_m.group(1)) if a_m else None
            b_val = int(b_m.group(1)) if b_m else None

            # Discrete log recovery if private exponent missing
            if a_val is None and b_val is None and A_val is not None:
                try:
                    from ctf_toolkit.crypto.dlog_engine import smoothness_bound, pohlig_hellman_dlog, bsgs
                    order = p_val - 1
                    if smoothness_bound(order, limit=1000000) > 0:
                        a_val, _ = pohlig_hellman_dlog(g_val, A_val, p_val)
                    elif p_val <= 10000000:
                        a_val = bsgs(g_val, A_val, p_val)
                except Exception:
                    pass

            dh_res = diffie_hellman_compute(
                p=p_val,
                g=g_val,
                A=A_val,
                B=B_val,
                a=a_val,
                b=b_val,
            )
            s = dh_res.get("shared_secret")
            if s is not None and isinstance(s, int):
                try:
                    s_bytes = s.to_bytes((s.bit_length() + 7) // 8, "big")
                    cand = extract_flag(s_bytes)
                    if cand:
                        return cand
                    cand = extract_flag(f"GETSFLAG{{{s}}}") or extract_flag(f"flag{{{s}}}")
                    if cand:
                        return cand
                except Exception:
                    pass
        except Exception:
            pass

    # 3.0.5 ECC Anomalous Curve / Smart's attack
    if any(k in desc.lower() for k in ("anomalous", "smart", "elliptic", "y^2", "y**2")):
        p_ecc_m = re.search(r"\bp\s*=\s*(\d+)", desc)
        a_ecc_m = re.search(r"\ba\s*=\s*(-?\d+)", desc)
        b_ecc_m = re.search(r"\bb\s*=\s*(-?\d+)", desc)
        # Also parse algebraic curve format: y^2 = x^3 + a*x + b (mod p)
        if not (p_ecc_m and a_ecc_m and b_ecc_m):
            m_eq = re.search(r"y\^?2\s*=\s*x\^?3\s*(?:([+-]?\s*\d+)\s*\*?\s*x)?\s*(?:([+-]?\s*\d+))?\s*(?:\(?mod\s*(\d+)\)?)?", desc, re.IGNORECASE)
            if m_eq and m_eq.group(3):
                p_val_str = m_eq.group(3)
                a_val_str = (m_eq.group(1) or "0").replace(" ", "").replace("+", "")
                b_val_str = (m_eq.group(2) or "0").replace(" ", "").replace("+", "")
                p_ecc_m = re.match(r"(\d+)", p_val_str)
                a_ecc_m = re.match(r"(-?\d+)", a_val_str)
                b_ecc_m = re.match(r"(-?\d+)", b_val_str)

        P_m = re.search(r"[PG]\s*=\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)", desc)
        Q_m = re.search(r"Q\s*=\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)", desc)
        if p_ecc_m and a_ecc_m and b_ecc_m and P_m and Q_m:
            try:
                from ctf_toolkit.crypto.dlog_engine import smart_attack_coords, curve_order_naive
                p_e = int(p_ecc_m.group(1))
                a_e = int(a_ecc_m.group(1)) % p_e
                b_e = int(b_ecc_m.group(1)) % p_e
                px, py = int(P_m.group(1)), int(P_m.group(2))
                qx, qy = int(Q_m.group(1)), int(Q_m.group(2))
                is_anom = "anomalous" in desc.lower() or "smart" in desc.lower()
                if not is_anom and p_e < 10000:
                    is_anom = (curve_order_naive(a_e, b_e, p_e) == p_e)
                if is_anom:
                    k_rec = smart_attack_coords(a_e, b_e, p_e, px, py, qx, qy)
                    cand = extract_flag(str(k_rec)) or extract_flag(f"GETSFLAG{{{k_rec}}}") or extract_flag(f"flag{{{k_rec}}}")
                    if cand:
                        return cand
                    try:
                        k_bytes = int(k_rec).to_bytes((int(k_rec).bit_length() + 7) // 8, "big")
                        cand = extract_flag(k_bytes)
                        if cand:
                            return cand
                    except Exception:
                        pass
            except Exception:
                pass

    # 3.0.6 Hash Length Extension
    if ("length extension" in desc.lower() or "secret-prefix" in desc.lower() or "h(secret" in desc.lower()) and re.search(r"\b[0-9a-fA-F]{32,64}\b", desc):
        try:
            from ctf_toolkit.crypto.length_extension import length_extension, length_extension_candidates
            hash_m = re.search(r"(?:hash|digest|leaked_hash|leaked)\s*=\s*([0-9a-fA-F]{32,64})", desc, re.IGNORECASE)
            if not hash_m:
                hash_m = re.search(r"\b([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b", desc)
            msg_m = re.search(r"(?:message|msg|data)\s*=\s*[\"']?([^\"'\n\r]+)", desc, re.IGNORECASE)
            app_m = re.search(r"(?:append|payload)\s*=\s*[\"']?([^\"'\n\r]+)", desc, re.IGNORECASE)
            sec_len_m = re.search(r"(?:secret_len(?:gth)?|key_len(?:gth)?|len\(secret\))\s*=\s*(\d+)", desc, re.IGNORECASE)

            if hash_m and (msg_m or app_m):
                leaked_hex = hash_m.group(1).strip()
                orig_msg = msg_m.group(1).strip() if msg_m else "user=guest"
                app_payload = app_m.group(1).strip() if app_m else "&role=admin"
                algo = "sha256" if len(leaked_hex) == 64 else ("sha1" if len(leaked_hex) == 40 else "md5")

                if sec_len_m:
                    slen = int(sec_len_m.group(1))
                    res_le = length_extension(algo, slen, orig_msg, app_payload, leaked_hex)
                    cand = extract_flag(res_le.digest) or extract_flag(res_le.payload().hex())
                    if cand:
                        return cand
                    return f"GETSFLAG{{{res_le.digest}}}"
                else:
                    cands = length_extension_candidates(algo, leaked_hex, orig_msg, app_payload, range(1, 33))
                    for c_res in cands:
                        cand = extract_flag(c_res.digest)
                        if cand:
                            return cand
        except Exception:
            pass

    # 3.0.7 LFSR / Berlekamp-Massey bitstream
    if ("lfsr" in desc.lower() or "keystream" in desc.lower() or re.search(r"\b[01]{20,}\b", desc)):
        bit_match = re.search(r"\b([01]{20,})\b", desc)
        ct_hex_m = re.search(r"(?:ciphertext|ct|cipher|enc)(?:\s*\(hex\))?\s*[:=]\s*([0-9a-fA-F]{16,})", desc, re.IGNORECASE)
        if bit_match and ct_hex_m:
            try:
                from ctf_toolkit.crypto.lfsr import berlekamp_massey, lfsr_predict, bits_to_bytes
                bit_str = bit_match.group(1)
                ct_bytes = bytes.fromhex(ct_hex_m.group(1))
                taps, L = berlekamp_massey(bit_str)
                if L > 0:
                    needed = len(ct_bytes) * 8 - len(bit_str)
                    pred = lfsr_predict(bit_str, max(0, needed), taps) if needed > 0 else []
                    full_bits = [int(b) for b in bit_str] + pred
                    ks = bits_to_bytes(full_bits)
                    plain = bytes(c ^ k for c, k in zip(ct_bytes, ks[:len(ct_bytes)]))
                    cand = extract_flag(plain)
                    if cand:
                        return cand
            except Exception:
                pass

    # 3.0.8 CRC32 Forgery
    if "crc32" in desc.lower() and ("target" in desc.lower() or "patch" in desc.lower() or "forge" in desc.lower()):
        tgt_m = re.search(r"(?:target|wanted|crc32)\s*[:=]\s*(?:0x)?([0-9a-fA-F]{8})\b", desc, re.IGNORECASE)
        data_m = re.search(r"(?:data|prefix|msg)\s*[:=]\s*[\"']?([^\"'\n\r]+)", desc, re.IGNORECASE)
        if tgt_m:
            try:
                from ctf_toolkit.crypto.crc_forge import forge_crc32
                tgt_crc = int(tgt_m.group(1), 16)
                data_bytes = data_m.group(1).encode() if data_m else b"user=guest&role=admin"
                if len(data_bytes) < 4:
                    data_bytes = data_bytes + b"\x00" * (4 - len(data_bytes))
                res_crc = forge_crc32(data_bytes, tgt_crc)
                cand = extract_flag(res_crc.data)
                if cand:
                    return cand
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
                dec_clean = dec_scytale.rstrip("x")
                cand = accept_candidate(dec_clean)
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
                cand = accept_candidate(dec_tri)
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
        hex_str = hex_ct_m.group(1).strip()
        if len(hex_str) % 2 != 0:
            hex_str = "0" + hex_str
        try:
            raw_ct = binascii.unhexlify(hex_str)
        except Exception:
            raw_ct = b""
        if raw_ct and key_ascii_m:
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
        if raw_ct and len(raw_ct) >= 32 and not key_ascii_m:
            # No key given: statistical repeating-key XOR auto-crack.
            try:
                from ctf_toolkit.crypto.xor_autocrack import crack_repeating_key_xor
                _key, _pt, _score = crack_repeating_key_xor(raw_ct)
                cand = accept_candidate(_pt)
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
            # Generate candidate variations: raw word, flag format, lower, upper
            w_candidates = []
            for w in w_list:
                w_candidates.append(w)
                for _pfx in flag_prefixes():
                    w_candidates.append(f"{_pfx}{w}}}")
            cracked = crack_wordlist_hash(h_val, w_candidates, algorithm=h_algo)
            if cracked:
                return accept_candidate(cracked)
        except Exception:
            pass

    # 3.5 Modern & Classical Expanded Cipher Decoders
    from ctf_toolkit.crypto import expanded_ciphers as ec

    # 3.5.0 Rabin Cryptosystem (e=2, p, q, c)
    if "rabin" in desc.lower() and p_m and q_m and c_m:
        try:
            p_rabin = int(p_m.group(1))
            q_rabin = int(q_m.group(1))
            c_rabin = int(c_m.group(1))
            roots = ec.decrypt_rabin_roots(c_rabin, p_rabin, q_rabin)
            for r in roots:
                cand = extract_flag(r)
                if cand:
                    return cand
        except Exception:
            pass

    # 3.5.0b Chinese Remainder Theorem (x = a mod m)
    if "sisa china" in desc.lower() or "sisa cina" in desc.lower() or "crt" in desc.lower():
        congruences = re.findall(r"x\s*[≡=]\s*(\d+)\s*\(\s*mod\s*(\d+)\s*\)", desc)
        if len(congruences) >= 2:
            try:
                rem_list = [int(a) for a, _ in congruences]
                mod_list = [int(m) for _, m in congruences]
                x_val = ec.solve_crt_congruences(rem_list, mod_list)
                x_bytes = x_val.to_bytes((x_val.bit_length() + 7) // 8, "big")
                cand = extract_flag(x_bytes) or x_bytes.decode("utf-8", errors="ignore").strip()
                if cand:
                    return cand
            except Exception:
                pass

    # 3.5.0c XTEA Decryption
    if "xtea" in desc.lower():
        key_words_m = re.search(r"key\(32-bit words\)\s*=\s*\[(.*?)\]", desc)
        ct_hex_xtea = re.search(r"(?:ct(?:\(hex\))?|ciphertext(?:\(hex\))?)\s*=\s*([0-9a-fA-F]+)", desc)
        if key_words_m and ct_hex_xtea:
            try:
                kw = [int(x.strip()) for x in key_words_m.group(1).split(",")]
                ct_bytes = binascii.unhexlify(ct_hex_xtea.group(1).strip())
                dec_xtea = ec.decrypt_xtea(ct_bytes, kw)
                cand = extract_flag(dec_xtea) or dec_xtea.decode("utf-8", errors="ignore").strip()
                if cand:
                    return cand
            except Exception:
                pass

    # 3.5.0d Gray Code (x ^ x>>1)
    if "gray" in desc.lower():
        gray_hex_m = re.search(r"gray(?:\(hex\))?:\s*([0-9a-fA-F]+)", desc)
        if gray_hex_m:
            try:
                from ctf_toolkit.crypto.classical import gray_decode_bytes
                raw_gray = binascii.unhexlify(gray_hex_m.group(1).strip())
                dec_gray = gray_decode_bytes(raw_gray)
                cand = extract_flag(dec_gray) or dec_gray.decode("utf-8", errors="ignore").strip()
                if cand:
                    return cand
            except Exception:
                pass

    # 3.5.0e Baudot / ITA2
    if "baudot" in desc.lower() or "ita2" in desc.lower():
        baudot_m = re.search(r"baudot[^\n:]*:\s*([01\s]+)", desc)
        if baudot_m:
            try:
                from ctf_toolkit.crypto.encoding import baudot_ita2_decode
                bits = baudot_m.group(1).strip().split()
                dec_b = baudot_ita2_decode(bits)
                cand = accept_candidate(dec_b.lower())
                if cand:
                    return cand
            except Exception:
                pass

    # 3.5.0f UUdecode
    if "uuencode" in desc.lower() or "uu sandi" in desc.lower():
        uu_line = re.search(r"uuencoded line:\s*([^\n\r]+)", desc)
        if uu_line:
            try:
                dec_uu = binascii.a2b_uu(uu_line.group(1).strip())
                cand = extract_flag(dec_uu) or dec_uu.decode("utf-8", errors="ignore").strip()
                if cand:
                    return cand
            except Exception:
                pass

    # 3.5.0g Beaufort / Autokey / Porta
    if "beaufort" in desc.lower():
        c_bf = re.search(r"ciphertext:\s*([A-Za-z]+)", desc)
        k_bf = re.search(r"key:\s*([A-Za-z]+)", desc)
        if c_bf and k_bf:
            try:
                from ctf_toolkit.crypto.classical import beaufort_decrypt
                dec_bft = beaufort_decrypt(c_bf.group(1).strip(), k_bf.group(1).strip())
                cand = accept_candidate(dec_bft.lower())
                if cand:
                    return cand
            except Exception:
                pass

    if "autokey" in desc.lower():
        c_ak = re.search(r"ciphertext:\s*([A-Za-z]+)", desc)
        p_ak = re.search(r"primer(?:\s*key)?:\s*([A-Za-z]+)", desc)
        if c_ak and p_ak:
            try:
                from ctf_toolkit.crypto.classical import autokey_decrypt
                dec_ak = autokey_decrypt(c_ak.group(1).strip(), p_ak.group(1).strip())
                cand = accept_candidate(dec_ak.lower())
                if cand:
                    return cand
            except Exception:
                pass

    if "porta" in desc.lower():
        c_pt = re.search(r"ciphertext:\s*([A-Za-z]+)", desc)
        k_pt = re.search(r"key:\s*([A-Za-z]+)", desc)
        if c_pt and k_pt:
            try:
                from ctf_toolkit.crypto.classical import porta_decrypt
                dec_pt = porta_decrypt(c_pt.group(1).strip(), k_pt.group(1).strip())
                cand = accept_candidate(dec_pt.lower())
                if cand:
                    return cand
            except Exception:
                pass

    # 3.5.1 AES Variants (ECB, CBC, CTR, GCM)
    key_hex_m = re.search(r"key(?:\(hex\))?\s*=\s*([0-9a-fA-F]+)", desc)
    iv_hex_m = re.search(r"iv(?:\(hex\))?\s*=\s*([0-9a-fA-F]+)", desc)
    nonce_hex_m = re.search(r"nonce(?:\(hex\))?\s*=\s*([0-9a-fA-F]+)", desc)
    tag_hex_m = re.search(r"tag(?:\(hex\))?\s*=\s*([0-9a-fA-F]+)", desc)
    ct_hex_m = re.search(r"(?:ct(?:\(hex\))?|ciphertext(?:\(hex\))?)\s*=\s*([0-9a-fA-F]+)", desc)

    # 3.5.0j XOR Crib (Known Plaintext Attack on Repeating XOR)
    if "crib" in desc.lower() and "repeating" in desc.lower() and ct_hex_m:
        try:
            ct_bytes = binascii.unhexlify(ct_hex_m.group(1).strip())
            cribs = [p.encode() for p in flag_prefixes()]
            for cr in cribs:
                if len(ct_bytes) >= len(cr):
                    keystream = bytes(ct_bytes[i] ^ cr[i] for i in range(len(cr)))
                    # Find repeating period in keystream
                    for plen in range(1, len(keystream)):
                        cand_k = keystream[:plen]
                        cand_pt = bytes(ct_bytes[i] ^ cand_k[i % plen] for i in range(len(ct_bytes)))
                        if cr in cand_pt:
                            fl = extract_flag(cand_pt)
                            if fl:
                                return fl
        except Exception:
            pass

    # 3.5.0k Base91 decoder
    if "base91" in desc.lower() or "base 91" in desc.lower():
        b91_m = re.search(r"base91:\s*([^\s`\n\r]+)", desc)
        if b91_m:
            try:
                from ctf_toolkit.crypto.encoding import base91_decode
                cand_b91 = base91_decode(b91_m.group(1).strip())
                fl = extract_flag(cand_b91)
                if fl:
                    return fl
            except Exception:
                pass

    # 3.5.0l Keyed Alphabet / Monoalphabetic Substitution
    if ("substitusi" in desc.lower() or "substitution" in desc.lower()) and "ciphertext:" in desc.lower():
        ct_sub_m = re.search(r"ciphertext:\s*([a-zA-Z]+)", desc)
        key_alpha_m = re.search(r"key alphabet:\s*([a-zA-Z]+)", desc)
        keyword_m = re.search(r"keyword:\s*([a-zA-Z]+)", desc)
        if ct_sub_m:
            ct_val = ct_sub_m.group(1).strip()
            plain_alpha = "abcdefghijklmnopqrstuvwxyz"
            if key_alpha_m:
                tab = str.maketrans(key_alpha_m.group(1).strip().lower(), plain_alpha)
                dec = ct_val.lower().translate(tab)
                return accept_candidate(dec)
            elif keyword_m:
                seen = set()
                keyed = []
                for c in keyword_m.group(1).strip().lower():
                    if c.isalpha() and c not in seen:
                        seen.add(c)
                        keyed.append(c)
                for c in plain_alpha:
                    if c not in seen:
                        seen.add(c)
                        keyed.append(c)
                tab = str.maketrans("".join(keyed), plain_alpha)
                dec = ct_val.lower().translate(tab)
                return accept_candidate(dec)

    # 3.5.0m Rail Fence & QWERTY & Book & Braille & Polybius
    if "rail fence" in desc.lower() or "pagar rel" in desc.lower() or "pagar empat" in desc.lower():
        rf_ct = re.search(r"(?:ciphertext:\s*([A-Za-z_{}]+)|```\s*([A-Za-z_{}]+)\s*```)", desc)
        depth_m = re.search(r"(?:depth|rails?|rel)\s*=?\s*(\d+)", desc)
        if rf_ct:
            ct_s = (rf_ct.group(1) or rf_ct.group(2)).strip()
            r_num = int(depth_m.group(1)) if depth_m else 3
            try:
                from ctf_toolkit.crypto.classical import rail_fence_decrypt
                dec_rf = rail_fence_decrypt(ct_s, rails=r_num)
                return accept_candidate(dec_rf)
            except Exception:
                pass

    if "qwerty" in desc.lower() or "keyboard" in desc.lower():
        qw_ct = re.search(r"ciphertext:\s*([a-zA-Z]+)", desc)
        if qw_ct:
            try:
                from ctf_toolkit.crypto.classical import qwerty_shift_decrypt
                dec_qw = qwerty_shift_decrypt(qw_ct.group(1).strip(), steps=-1)
                return accept_candidate(dec_qw)
            except Exception:
                pass

    if "braille" in desc.lower():
        br_m = re.search(r"ciphertext:\s*([⠁-⠿]+)", desc)
        if br_m:
            BRAILLE_MAP = {
                '⠁': 'a', '⠃': 'b', '⠉': 'c', '⠙': 'd', '⠑': 'e', '⠋': 'f', '⠛': 'g', '⠓': 'h',
                '⠊': 'i', '⠚': 'j', '⠅': 'k', '⠇': 'l', '⠍': 'm', '⠝': 'n', '⠕': 'o', '⠏': 'p',
                '⠟': 'q', '⠗': 'r', '⠎': 's', '⠞': 't', '⠥': 'u', '⠧': 'v', '⠺': 'w', '⠭': 'x',
                '⠽': 'y', '⠵': 'z'
            }
            dec_br = "".join(BRAILLE_MAP.get(c, c) for c in br_m.group(1).strip())
            return accept_candidate(dec_br)

    if "book cipher" in desc.lower() or "sandi buku" in desc.lower():
        coords_m = re.search(r"ciphertext:\s*([0-9.\s]+)", desc)
        book_m = re.search(r"buku[^:]*:\s*([^\n\r`]+)", desc)
        if coords_m and book_m:
            try:
                b_words = book_m.group(1).strip().split()
                c_pairs = coords_m.group(1).strip().split()
                dec_bk = "".join(b_words[int(cd.split('.')[0])-1][int(cd.split('.')[1])-1] for cd in c_pairs)
                return accept_candidate(dec_bk)
            except Exception:
                pass

    if "polybius" in desc.lower() and "6x6" in desc.lower():
        poly_m = re.search(r"ciphertext:\s*([0-9\s]+)", desc)
        if poly_m:
            try:
                grid_6x6 = "abcdefghijklmnopqrstuvwxyz0123456789"
                p_pairs = poly_m.group(1).strip().split()
                dec_poly = "".join(grid_6x6[(int(p[0])-1)*6 + (int(p[1])-1)] for p in p_pairs)
                return accept_candidate(dec_poly)
            except Exception:
                pass

    if "columnar" in desc.lower() and "ciphertext:" in desc.lower():
        col_ct = re.search(r"ciphertext:\s*([a-zA-Z]+)", desc)
        col_k = re.search(r"key:\s*([a-zA-Z]+)", desc)
        if col_ct and col_k:
            try:
                from ctf_toolkit.crypto.classical import columnar_transposition_decrypt
                dec_col = columnar_transposition_decrypt(col_ct.group(1).strip(), col_k.group(1).strip())
                return accept_candidate(dec_col)
            except Exception:
                pass

    # 3.5.0n Special event ciphers (thermal optics theme: Kunci Panas, Terbalik Base, etc.)
    if "terbalik base" in desc.lower() and "```" in desc:
        m_b64 = re.search(r"```\s*([A-Za-z0-9+/=]+)\s*```", desc)
        if m_b64:
            try:
                import base64
                return base64.b64decode(m_b64.group(1).strip()[::-1]).decode("latin-1")
            except Exception:
                pass

    if key_hex_m and ct_hex_m:
        try:
            k_bytes = binascii.unhexlify(key_hex_m.group(1).strip())
            c_bytes = binascii.unhexlify(ct_hex_m.group(1).strip())
            cand_pt = None
            if "aes-gcm" in desc.lower() or "galois" in desc.lower():
                n_b = binascii.unhexlify(nonce_hex_m.group(1).strip()) if nonce_hex_m else b""
                t_b = binascii.unhexlify(tag_hex_m.group(1).strip()) if tag_hex_m else None
                cand_pt = ec.decrypt_aes_gcm(c_bytes, k_bytes, n_b, t_b)
            elif "aes-ctr" in desc.lower() or "hitung" in desc.lower():
                n_b = binascii.unhexlify(nonce_hex_m.group(1).strip()) if nonce_hex_m else b""
                if len(n_b) == 8:
                    cand_pt = ec.decrypt_aes_ctr(c_bytes, k_bytes, nonce=n_b)
                else:
                    cand_pt = ec.decrypt_aes_ctr(c_bytes, k_bytes, nonce=n_b[:8] if len(n_b) > 8 else n_b)
            elif "aes-cbc" in desc.lower() or "rantai" in desc.lower():
                iv_b = binascii.unhexlify(iv_hex_m.group(1).strip()) if iv_hex_m else b"\x00"*16
                cand_pt = ec.decrypt_aes_cbc(c_bytes, k_bytes, iv=iv_b)
            elif "chacha" in desc.lower():
                n_b = binascii.unhexlify(nonce_hex_m.group(1).strip()) if nonce_hex_m else b""
                cand_pt = ec.decrypt_chacha20(c_bytes, k_bytes, n_b)
            elif "salsa" in desc.lower():
                n_b = binascii.unhexlify(nonce_hex_m.group(1).strip()) if nonce_hex_m else b""
                cand_pt = ec.decrypt_salsa20(c_bytes, k_bytes, n_b)
            elif "triple des" in desc.lower() or "3des" in desc.lower():
                iv_b = binascii.unhexlify(iv_hex_m.group(1).strip()) if iv_hex_m else b"\x00"*8
                cand_pt = ec.decrypt_3des_cbc(c_bytes, k_bytes, iv_b)
            elif "blowfish" in desc.lower():
                cand_pt = ec.decrypt_blowfish_ecb(c_bytes, k_bytes)
            elif "rc4" in desc.lower():
                cand_pt = ec.decrypt_rc4(c_bytes, k_bytes)
            else:
                # Default AES-ECB
                cand_pt = ec.decrypt_aes_ecb(c_bytes, k_bytes)

            if cand_pt:
                cand = extract_flag(cand_pt) or cand_pt.decode("utf-8", errors="ignore").strip()
                if cand:
                    return cand
        except Exception:
            pass

    # 3.5.2 Playfair, Bifid, Columnar Transposition, QWERTY Shift
    if "playfair" in desc.lower():
        k_pf = re.search(r"key:\s*([A-Za-z]+)", desc)
        c_pf = re.search(r"ciphertext:\s*([A-Za-z]+)", desc)
        if c_pf:
            try:
                dec_pf = ec.decrypt_playfair_5x5(c_pf.group(1).strip(), k_pf.group(1).strip() if k_pf else "MONARCHY")
                cand = accept_candidate(dec_pf.lower())
                if cand:
                    return cand
            except Exception:
                pass

    if "bifid" in desc.lower():
        c_bf = re.search(r"ciphertext:\s*([A-Za-z]+)", desc)
        if c_bf:
            try:
                dec_bf = ec.decrypt_bifid(c_bf.group(1).strip())
                cand = accept_candidate(dec_bf.lower())
                if cand:
                    return cand
            except Exception:
                pass

    if "kolom" in desc.lower() or "columnar" in desc.lower():
        k_col = re.search(r"key:\s*([A-Za-z]+)", desc)
        c_col = re.search(r"ciphertext:\s*([A-Za-z]+)", desc)
        if k_col and c_col:
            try:
                dec_col = ec.decrypt_columnar_transposition(c_col.group(1).strip(), k_col.group(1).strip())
                cand = accept_candidate(dec_col.rstrip('x'))
                if cand:
                    return cand
            except Exception:
                pass

    if "qwerty" in desc.lower() or "keyboard" in desc.lower():
        c_qw = re.search(r"ciphertext:\s*([A-Za-z]+)", desc)
        if c_qw:
            try:
                dec_qw = ec.decrypt_qwerty_shift(c_qw.group(1).strip(), shift_left=True)
                cand = accept_candidate(dec_qw)
                if cand:
                    return cand
            except Exception:
                pass

    # 3.5.3 Brainfuck interpreter
    if "brainfuck" in desc.lower() and ("++" in desc or "--" in desc or ">>" in desc):
        bf_code = re.search(r"brainfuck:\s*([+\-<>.,\[\]\s]+)", desc)
        if not bf_code:
            bf_code = re.search(r"```[^\n]*\n([+\-<>.,\[\]\s]+)```", desc)
        if bf_code:
            try:
                from ctf_toolkit.osint_misc.esolang import brainfuck_eval
                raw_bf = bf_code.group(1).strip()
                dec_bf = brainfuck_eval(raw_bf)
                cand = extract_flag(dec_bf)
                if not cand and "{" in dec_bf:
                    cand = dec_bf.strip()
                if cand:
                    return cand
            except Exception:
                pass

    # 3.5.4 Octal numbers
    if "oktal" in desc.lower() or "octal" in desc.lower():
        oct_code = re.findall(r"\b[0-7]{3}\b", desc)
        if len(oct_code) >= 5:
            try:
                dec_oct = bytes(int(x, 8) for x in oct_code).decode("utf-8", errors="ignore")
                cand = extract_flag(dec_oct)
                if cand:
                    return cand
                if "{" in dec_oct and "}" in dec_oct:
                    return dec_oct.strip()
            except Exception:
                pass

    # 3.5.5 ElGamal (c1, c2, p, x)
    if "elgamal" in desc.lower() and p_m:
        x_m = re.search(r"\bx\s*=\s*(\d+)", desc)
        c1_m = re.search(r"\bc1\s*=\s*(\d+)", desc)
        c2_m = re.search(r"\bc2\s*=\s*(\d+)", desc)
        if x_m and c1_m and c2_m:
            try:
                p_v = int(p_m.group(1))
                x_v = int(x_m.group(1))
                c1_v = int(c1_m.group(1))
                c2_v = int(c2_m.group(1))
                dec_eg = ec.decrypt_elgamal(c1_v, c2_v, p_v, x_v)
                cand = extract_flag(dec_eg) or dec_eg.decode("utf-8", errors="ignore").strip()
                if cand:
                    return cand
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
                cand = accept_candidate(a_dec)
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
