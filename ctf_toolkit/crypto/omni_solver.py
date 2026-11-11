"""Omni-solver backend engine for Apexsions CTF Web Workbench.

Provides high-level intent-driven resolution primitives matching and exceeding
tools.getsflag.com:
1. auto_solve_hub: Master single-shot triage & solver for raw text, params, hex, base64, hashes, tokens.
2. rsa_intent_solver: Parameter parsing, multi-prime, small e, Wiener, Fermat, Hastad.
3. classical_intent_solver: Caesar (all 25 shifts), Affine brute, Vigenere, Railfence, Single-byte XOR brute.
4. web_intent_solver: JWT decode/verify/crack, hash cracking, URL/HTML/Base64/Hex transform.
5. blockchain_intent_solver: Calldata decode, Keccak256, Function selector, CREATE/CREATE2, EIP-55.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from typing import Any

from ctf_toolkit.crypto.auto_decode import auto_decode_layers
from ctf_toolkit.crypto.auto_solver import solve_crypto_task
from ctf_toolkit.crypto.cipher_id import identify_cipher_text, identify_hash_format
from ctf_toolkit.crypto.classical import (
    a1z26_decode,
    affine_decrypt,
    caesar_bruteforce,
    morse_decode,
    rail_fence_decrypt,
    vigenere_decrypt,
)
from ctf_toolkit.crypto.dh_ecc_tool import diffie_hellman_compute, ecc_point_operation
from ctf_toolkit.crypto.hashes import crack_numeric_hash, crack_wordlist_hash
from ctf_toolkit.crypto.rsa import (
    common_modulus_attack,
    hastad_broadcast,
    rsa_multiprime_decrypt,
    rsa_solve_phi_e_c,
    rsa_solve_pqec,
    wiener_attack,
)
from ctf_toolkit.crypto.rsa_auto import solve_rsa_auto
from ctf_toolkit.reversing.transforms import xor_bruteforce_single
from ctf_toolkit.utils.flag_manager import get_flag_manager
from ctf_toolkit.web.jwt_attacks import jwt_crack_hs256, jwt_forge_none, jwt_sign_hs256

COMMON_SECRETS = [
    "secret", "admin", "password", "123456", "root", "key", "jwt",
    "supersecret", "test", "development", "production", "flag",
    "getsflag", "nueva", "apexsions", "ctf", "cyber", "token", "auth",
]


def auto_solve_hub(raw_text: str) -> dict[str, Any]:
    """Master single-click solver. Accepts anything and runs full pipeline."""
    text = (raw_text or "").strip()
    if not text:
        return {"success": False, "error": "Input text is empty."}

    res: dict[str, Any] = {
        "success": True,
        "input_preview": text[:120] + ("..." if len(text) > 120 else ""),
        "input_length": len(text),
        "steps_taken": [],
        "flags_found": [],
        "best_result": None,
        "type_detected": "Unknown",
    }

    # Step 0: Immediate flag extraction
    mgr = get_flag_manager()
    initial_flags = mgr.extract_flags(text)
    if initial_flags:
        res["flags_found"].extend(initial_flags)
        res["best_result"] = initial_flags[0]["flag"]
        res["type_detected"] = f"Plain Flag ({initial_flags[0]['name']})"
        res["steps_taken"].append(f"Immediate regex hit for template '{initial_flags[0]['name']}'.")
        return res

    # Step 1: Check for RSA / DH / Crypto parameter pattern (e.g. n = ..., e = ...)
    if any(k in text for k in ("n =", "n=", "p =", "p=", "c =", "c=", "g =", "phi =")):
        res["steps_taken"].append("Detected math/crypto parameter declarations. Routing to RSA/DH engine.")
        crypto_sol = solve_crypto_task(text)
        if crypto_sol:
            res["type_detected"] = "Crypto Parameter Script"
            res["best_result"] = crypto_sol
            res["steps_taken"].append("solve_crypto_task resolved valid output.")
            flags = mgr.extract_flags(crypto_sol)
            if flags:
                res["flags_found"].extend(flags)
            return res

    # Step 2: Check for JWT Token
    if text.count(".") == 2 and text.startswith("eyJ"):
        res["steps_taken"].append("Detected JWT token structure.")
        jwt_res = solve_jwt_intent(text)
        res["type_detected"] = "JSON Web Token (JWT)"
        res["jwt_analysis"] = jwt_res
        res["best_result"] = jwt_res.get("payload")
        if jwt_res.get("cracked_secret"):
            res["steps_taken"].append(f"HS256 secret cracked: '{jwt_res['cracked_secret']}'.")
        return res

    # Step 3: Check for Morse
    if re.fullmatch(r"[.\- /_\n]+", text) and any(c in text for c in (".-", "-.", "...", "---")):
        res["steps_taken"].append("Detected Morse code alphabet.")
        try:
            cand = morse_decode(text)
            if cand:
                res["type_detected"] = "Morse Code"
                res["best_result"] = cand
                flags = mgr.extract_flags(cand)
                if flags:
                    res["flags_found"].extend(flags)
                return res
        except Exception:
            pass

    # Step 4: Check for A1Z26 (e.g. 7-5-20-19-6-12-1-7)
    if re.fullmatch(r"(?:\d{1,2}[ -/,\.]?)+", text) and any(s in text for s in ("-", " ", ",")):
        try:
            cand = a1z26_decode(text)
            if cand and len(cand) >= 4:
                res["type_detected"] = "A1Z26 Positional Cipher"
                res["best_result"] = cand
                flags = mgr.extract_flags(cand)
                if flags:
                    res["flags_found"].extend(flags)
                return res
        except Exception:
            pass

    # Step 5: Check for Hash
    if re.fullmatch(r"[0-9a-fA-F]{32,128}", text):
        res["steps_taken"].append("Detected hexadecimal digest matching common hash algorithms.")
        h_info = identify_hash_format(text)
        res["hash_analysis"] = h_info
        res["type_detected"] = f"Hash ({h_info.get('format', 'Hex Hash')})"
        # Attempt instant cracking
        algo = "md5" if len(text) == 32 else ("sha1" if len(text) == 40 else ("sha256" if len(text) == 64 else "sha512"))
        cracked = crack_wordlist_hash(text, COMMON_SECRETS, algorithm=algo)
        if not cracked and len(text) == 32:
            cracked = crack_numeric_hash(text, max_digits=6, algorithm="md5")
        if cracked:
            res["cracked_preimage"] = cracked
            res["best_result"] = f"Preimage: {cracked}"
            res["steps_taken"].append(f"Cracked preimage: '{cracked}'.")
            return res

    # Step 6: Multi-layer Auto Peeling (Base64, Hex, Base32, Base85, ROT, XOR)
    try:
        peeled = auto_decode_layers(text, max_layers=8)
        if peeled:
            peeled_str = peeled.decode("utf-8", errors="replace").strip()
            if peeled_str and peeled_str != text:
                res["steps_taken"].append("Multi-layer peeler decomposed nested encoding layers.")
                res["type_detected"] = "Multi-Layer Encoded Stream"
                res["best_result"] = peeled_str
                flags = mgr.extract_flags(peeled_str)
                if flags:
                    res["flags_found"].extend(flags)
                return res
    except Exception:
        pass

    # Step 7: Single-byte XOR brute check for flag pattern
    try:
        raw_b = binascii.unhexlify(text) if (len(text) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", text)) else text.encode("utf-8")
        xor_hits = xor_bruteforce_single(raw_b)
        for key_byte, score, cand_b in xor_hits[:5]:
            cand_s = cand_b.decode("utf-8", errors="ignore")
            flags = mgr.extract_flags(cand_s)
            if flags:
                res["type_detected"] = f"Single-Byte XOR (Key 0x{key_byte:02x})"
                res["best_result"] = cand_s
                res["flags_found"].extend(flags)
                res["steps_taken"].append(f"XOR brute-force matched flag pattern with key 0x{key_byte:02x}.")
                return res
    except Exception:
        pass

    # Fallback: Cipher identification metadata
    cid = identify_cipher_text(text)
    res["cipher_identification"] = cid
    res["best_result"] = f"Raw text with IoC {cid.get('ioc', 0.0):.4f}, entropy {cid.get('entropy', 0.0):.2f}. Likely: {', '.join(cid.get('likely_types', ['Plaintext']))}."
    return res


def solve_rsa_intent(
    raw_desc: str = "",
    n: int | None = None,
    e: int | None = None,
    c: int | None = None,
    p: int | None = None,
    q: int | None = None,
    phi: int | None = None,
    d: int | None = None,
    primes: list[int] | None = None,
) -> dict[str, Any]:
    """Comprehensive RSA intent resolver for any combination of parameters or raw text."""
    if raw_desc.strip():
        # Parse params from text
        desc = raw_desc
        p_m = re.search(r"\bp\s*=\s*(\d+)", desc)
        q_m = re.search(r"\bq\s*=\s*(\d+)", desc)
        e_m = re.search(r"\be\s*=\s*(\d+)", desc)
        c_m = re.search(r"\bc\s*=\s*(\d+)", desc)
        n_m = re.search(r"\bn\s*=\s*(\d+)", desc)
        phi_m = re.search(r"\b(?:phi|φ)\s*=\s*(\d+)", desc, re.IGNORECASE)
        d_m = re.search(r"\bd\s*=\s*(\d+)", desc)

        if not n and n_m: n = int(n_m.group(1))
        if not e and e_m: e = int(e_m.group(1))
        if not c and c_m: c = int(c_m.group(1))
        if not p and p_m: p = int(p_m.group(1))
        if not q and q_m: q = int(q_m.group(1))
        if not phi and phi_m: phi = int(phi_m.group(1))
        if not d and d_m: d = int(d_m.group(1))

        # Check for multiple primes: r = ..., s = ...
        r_m = re.search(r"\br\s*=\s*(\d+)", desc)
        if r_m and not primes:
            primes = []
            if p: primes.append(p)
            if q: primes.append(q)
            primes.append(int(r_m.group(1)))
            s_m = re.search(r"\bs\s*=\s*(\d+)", desc)
            if s_m: primes.append(int(s_m.group(1)))

    res: dict[str, Any] = {"success": False, "method": None, "plaintext": None, "flag": None}

    # Case A: Multi-prime (p, q, r, ...)
    if primes and len(primes) >= 3 and e and c:
        try:
            m = rsa_multiprime_decrypt(primes, e, c)
            pt = m.to_bytes((m.bit_length() + 7) // 8, "big")
            res["success"] = True
            res["method"] = f"Multi-Prime RSA ({len(primes)} factors)"
            res["plaintext"] = pt.decode("utf-8", errors="replace")
            res["flag"] = get_flag_manager().find_first_flag(pt)
            return res
        except Exception as err:
            res["error"] = f"Multi-prime failed: {err}"

    # Case B: Known p, q
    if p and q and e and c:
        try:
            pt = rsa_solve_pqec(p, q, e, c)
            res["success"] = True
            res["method"] = "Known Primes (p, q)"
            res["plaintext"] = pt.decode("utf-8", errors="replace")
            res["flag"] = get_flag_manager().find_first_flag(pt)
            return res
        except Exception as err:
            res["error"] = f"p, q solve failed: {err}"

    # Case C: Known phi
    if n and phi and e and c:
        try:
            pt = rsa_solve_phi_e_c(n, phi, e, c)
            res["success"] = True
            res["method"] = "Known Totient (phi)"
            res["plaintext"] = pt.decode("utf-8", errors="replace")
            res["flag"] = get_flag_manager().find_first_flag(pt)
            return res
        except Exception as err:
            res["error"] = f"phi solve failed: {err}"

    # Case D: Known d
    if n and d and c:
        try:
            m = pow(c, d, n)
            pt = m.to_bytes((m.bit_length() + 7) // 8, "big")
            res["success"] = True
            res["method"] = "Direct Decryption (Known d)"
            res["plaintext"] = pt.decode("utf-8", errors="replace")
            res["flag"] = get_flag_manager().find_first_flag(pt)
            return res
        except Exception as err:
            res["error"] = f"d decrypt failed: {err}"

    # Case E: Autonomous attack suite (Wiener, Fermat, small e, small prime)
    if n and e and c:
        try:
            auto_res = solve_rsa_auto(n=n, e=e, c=c)
            if auto_res and isinstance(auto_res, dict) and "plaintext" in auto_res:
                pt_b = auto_res["plaintext"]
                res["success"] = True
                res["method"] = f"Autonomous Attack: {auto_res.get('observed_attack', 'auto')}"
                res["plaintext"] = pt_b.decode("utf-8", errors="replace") if isinstance(pt_b, bytes) else str(pt_b)
                res["flag"] = get_flag_manager().find_first_flag(res["plaintext"])
                res["details"] = {k: v for k, v in auto_res.items() if k != "plaintext"}
                return res
        except Exception as err:
            res["error"] = f"Auto attacks failed: {err}"

    if not res["success"] and not res.get("error"):
        res["error"] = "Insufficient parameters. Provide (n, e, c) or (p, q, e, c) or paste challenge description."
    return res


def solve_classical_intent(
    text: str,
    operation: str = "caesar",
    key: str = "",
    shift: int = 3,
    a: int = 1,
    b: int = 0,
    rails: int = 3,
    is_hex: bool = False,
) -> dict[str, Any]:
    """Execute classical cipher transformations with automatic flag detection."""
    text = (text or "").strip()
    if not text:
        return {"success": False, "error": "No text provided."}

    mgr = get_flag_manager()
    res: dict[str, Any] = {"success": True, "operation": operation, "flag": None}

    if operation == "caesar":
        shifts = caesar_bruteforce(text)
        res["all_shifts"] = [{"shift": s, "text": t} for s, t in shifts]
        for s, cand in shifts:
            fl = mgr.find_first_flag(cand)
            if fl:
                res["flag"] = fl
                res["matched_shift"] = s
                break
        res["result"] = res.get("flag") or (shifts[shift % 26][1] if shifts else "")

    elif operation == "affine":
        results = []
        inv_map = {1:1, 3:9, 5:21, 7:15, 9:3, 11:19, 15:7, 17:23, 19:11, 21:5, 23:17, 25:25}
        for ca in inv_map.keys():
            for cb in range(26):
                dec = affine_decrypt(text, ca, cb)
                fl = mgr.find_first_flag(dec)
                if fl:
                    res["flag"] = fl
                    res["a"] = ca
                    res["b"] = cb
                    res["result"] = dec
                    return res
                results.append({"a": ca, "b": cb, "text": dec})
        res["candidates"] = results[:30]
        res["result"] = f"Generated {len(results)} affine variants. Check candidates list."

    elif operation == "vigenere":
        if key:
            dec = vigenere_decrypt(text, key)
            res["result"] = dec
            res["flag"] = mgr.find_first_flag(dec)
        else:
            # Auto-brute top keys
            top_keys = ["CTF", "KEY", "SECRET", "FLAG", "CIPHER", "CRYPTO", "ADMIN", "GETSFLAG"]
            cands = []
            for k in top_keys:
                d = vigenere_decrypt(text, k)
                fl = mgr.find_first_flag(d)
                if fl:
                    res["flag"] = fl
                    res["key_found"] = k
                    res["result"] = d
                    return res
                cands.append({"key": k, "text": d})
            res["candidates"] = cands
            res["result"] = "Tested common Vigenere keys. Supply key for exact decode."

    elif operation == "railfence":
        dec = rail_fence_decrypt(text, rails=rails)
        res["result"] = dec
        res["flag"] = mgr.find_first_flag(dec)

    elif operation == "xor":
        try:
            raw_b = binascii.unhexlify(text) if is_hex else text.encode("utf-8")
            if key:
                key_b = key.encode("utf-8")
                xored = bytes(b ^ key_b[i % len(key_b)] for i, b in enumerate(raw_b))
                dec_s = xored.decode("utf-8", errors="replace")
                res["result"] = dec_s
                res["flag"] = mgr.find_first_flag(dec_s)
            else:
                hits = xor_bruteforce_single(raw_b)
                cands = []
                for kbyte, score, cb in hits[:32]:
                    cs = cb.decode("utf-8", errors="replace")
                    fl = mgr.find_first_flag(cs)
                    if fl and not res["flag"]:
                        res["flag"] = fl
                        res["key_found"] = f"0x{kbyte:02x}"
                        res["result"] = cs
                    cands.append({"key": f"0x{kbyte:02x}", "text": cs[:100]})
                res["candidates"] = cands
                if not res["flag"] and cands:
                    res["result"] = cands[0]["text"]
        except Exception as e:
            res["success"] = False
            res["error"] = str(e)

    return res


def solve_jwt_intent(token: str, extra_secret: str = "") -> dict[str, Any]:
    """Parse, decode unverified, and attempt offline HS256 crack on JWT."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return {"success": False, "error": "Invalid JWT format (requires header.payload.signature)."}

    def _b64pad(s: str) -> bytes:
        return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))

    res: dict[str, Any] = {"success": True}
    try:
        header_raw = _b64pad(parts[0]).decode("utf-8", errors="replace")
        payload_raw = _b64pad(parts[1]).decode("utf-8", errors="replace")
        res["header"] = json.loads(header_raw)
        res["payload"] = json.loads(payload_raw)
    except Exception as e:
        res["error_parsing"] = str(e)
        return res

    # Generate Alg None bypass token
    try:
        res["forged_alg_none"] = jwt_forge_none(res["payload"])
    except Exception:
        pass

    # Attempt HS256 wordlist crack
    cands = list(COMMON_SECRETS)
    if extra_secret:
        cands.extend([s.strip() for s in extra_secret.split(",") if s.strip()])

    cracked = jwt_crack_hs256(token, cands)
    res["cracked_secret"] = cracked
    return res
