from __future__ import annotations

from typing import Any
from Crypto.PublicKey import RSA

from ctf_toolkit.crypto.rsa import (
    factor_integer_auto,
    fermat_factor,
    int_to_bytes,
    integer_nth_root,
    phi_from_primes,
    pollard_p_minus_1,
    rsa_factor_small,
    rsa_solve_phi_e_c,
    rsa_solve_pqec,
    wiener_attack,
)
from ctf_toolkit.utils.math import gcd, modinv


def parse_pem_key(pem_or_der: str | bytes) -> dict[str, int]:
    """
    Parse PEM, DER, or OpenSSH RSA public/private key and return extracted parameters
    (`n`, `e`, and if private: `d`, `p`, `q`, `u`).
    """
    key = RSA.import_key(pem_or_der)
    info: dict[str, int] = {
        "n": int(key.n),
        "e": int(key.e),
        "bits": int(key.size_in_bits()),
    }
    if key.has_private():
        info["d"] = int(key.d)
        info["p"] = int(key.p)
        info["q"] = int(key.q)
    return info


def recover_rsa_dp_leak(n: int, e: int, dp: int, c: int) -> bytes | None:
    """Recover RSA plaintext when CRT exponent dp = d mod (p - 1) is leaked."""
    for k in range(1, e):
        if (e * dp - 1) % k == 0:
            p_cand = (e * dp - 1) // k + 1
            if 1 < p_cand < n and n % p_cand == 0:
                q_cand = n // p_cand
                return rsa_solve_pqec(p_cand, q_cand, e, c)
    return None


def solve_rsa_auto(
    n: int,
    e: int,
    c: int,
    dp: int | None = None,
    phi: int | None = None,
    d: int | None = None,
) -> dict[str, Any]:
    """
    Autonomous multi-attack RSA orchestrator (`RsaCtfTool` style).
    Sequentially tests:
      1. Direct d or phi if provided
      2. e == 1 identity plaintext
      3. Small e exact root (e <= 17 and m^e < n)
      4. Leaked CRT dp recovery
      5. Small prime factor trial division
      6. Wiener continued fractions attack (large e / small d)
      7. Fermat close-primes factorization
      8. Pollard p-1 smooth totient factorization
      9. Full offline factorization cascade (incl. Pollard rho, sympy)
     10. FactorDB online lookup (last resort, needs network)
    """
    if d is not None:
        pt = int_to_bytes(pow(c, d, n))
        return {"attack": "direct_d", "plaintext": pt, "d": d}

    if phi is not None:
        pt = rsa_solve_phi_e_c(n, phi, e, c)
        return {"attack": "direct_phi", "plaintext": pt, "phi": phi}

    if e == 1:
        pt = int_to_bytes(c)
        return {"attack": "e_equals_1", "plaintext": pt}

    if e <= 17:
        root = integer_nth_root(c, e)
        if root**e == c:
            return {"attack": "small_e_nth_root", "plaintext": int_to_bytes(root)}

    if dp is not None:
        pt_dp = recover_rsa_dp_leak(n, e, dp, c)
        if pt_dp is not None:
            return {"attack": "dp_leak", "plaintext": pt_dp}

    # Small prime factor check
    small_res = rsa_factor_small(n, e, c, limit=200_000)
    if isinstance(small_res, bytes):
        return {"observed_attack": "small_prime_factor", "plaintext": small_res}

    # Wiener's attack
    w_d = wiener_attack(e, n)
    if w_d is not None:
        return {"attack": "wiener", "plaintext": int_to_bytes(pow(c, w_d, n)), "d": w_d}

    # Fermat factorization (close primes)
    fermat_res = fermat_factor(n, max_iter=2_000_000)
    if fermat_res is not None:
        p, q = fermat_res
        return {"observed_attack": "fermat", "plaintext": rsa_solve_pqec(p, q, e, c), "p": p, "q": q}

    # Pollard p - 1 (smooth p-1)
    p_pollard = pollard_p_minus_1(n, B=100_000)
    if p_pollard is not None and 1 < p_pollard < n:
        q_pollard = n // p_pollard
        if gcd(e, (p_pollard - 1) * (q_pollard - 1)) == 1:
            return {
                "attack": "pollard_p_minus_1",
                "plaintext": rsa_solve_pqec(p_pollard, q_pollard, e, c),
                "p": p_pollard,
                "q": q_pollard,
            }

    # Full offline factorization cascade (trial division, Fermat, Pollard
    # p-1, Pollard rho, sympy) — covers rho-solvable moduli the steps above miss.
    try:
        fac, _fac_strategy = factor_integer_auto(n)
        flat: list[int] = []
        if isinstance(fac, (list, tuple)):
            for f_item in fac:
                if isinstance(f_item, (list, tuple)):
                    flat.extend(int(x) for x in f_item)
                elif isinstance(f_item, int):
                    flat.append(f_item)
        if len(flat) >= 2:
            phi_fac = phi_from_primes(flat)
            if gcd(e, phi_fac) == 1:
                d_fac = modinv(e, phi_fac)
                return {
                    "observed_attack": "factor_cascade",
                    "plaintext": int_to_bytes(pow(c, d_fac, n)),
                    "d": d_fac,
                    "factors": flat,
                }
    except Exception:
        pass

    # FactorDB online oracle check — LAST resort: offline methods first, so
    # results do not depend on network access or a third-party database.
    try:
        from ctf_toolkit.crypto.factordb import factordb_factor
        fdb_factors = factordb_factor(n, timeout=4.0)
        if fdb_factors and len(fdb_factors) >= 2:
            phi_fdb = 1
            for f_item in fdb_factors:
                phi_fdb *= (f_item - 1)
            if gcd(e, phi_fdb) == 1:
                d_cand = modinv(e, phi_fdb)
                pt_fdb = int_to_bytes(pow(c, d_cand, n))
                return {
                    "observed_attack": "factordb_lookup",
                    "plaintext": pt_fdb,
                    "d": d_cand,
                    "factors": fdb_factors,
                }
    except Exception:
        pass

    return {"attack": "unsolved", "plaintext": b""}
