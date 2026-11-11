from __future__ import annotations

from ctf_toolkit.crypto.ecc import Point, ecc_point_add, ecc_scalar_mul
from ctf_toolkit.utils.math import modinv


def is_point_on_curve(P: Point, a: int, b: int, p: int) -> bool:
    """Verify if point P(x, y) satisfies y^2 = x^3 + a*x + b (mod p)."""
    if P is None:
        return True
    x, y = P
    return (y * y) % p == (x * x * x + a * x + b) % p


def diffie_hellman_compute(
    p: int,
    g: int,
    A: int | None = None,
    B: int | None = None,
    a: int | None = None,
    b: int | None = None,
) -> dict[str, int | str | None]:
    """
    Diffie-Hellman Key Exchange Solver:
    - If a is provided and B is provided: shared = B^a mod p
    - If b is provided and A is provided: shared = A^b mod p
    - If both privates (a, b) provided: compute A, B, and shared
    - If neither private is provided but p is small (<= 2^64): attempt discrete log (BSGS via sympy)
    """
    result: dict[str, int | str | None] = {
        "p": p,
        "g": g,
        "A": A,
        "B": B,
        "a": a,
        "b": b,
        "shared_secret": None,
        "shared_secret_hex": None,
    }

    # Recover missing public keys if privates known
    if a is not None and A is None:
        A = pow(g, a, p)
        result["A"] = A
    if b is not None and B is None:
        B = pow(g, b, p)
        result["B"] = B

    # Direct shared secret computation
    if a is not None and B is not None:
        s = pow(B, a, p)
        result["shared_secret"] = s
        result["shared_secret_hex"] = hex(s)
        return result

    if b is not None and A is not None:
        s = pow(A, b, p)
        result["shared_secret"] = s
        result["shared_secret_hex"] = hex(s)
        return result

    # If neither private known, crack via discrete log if p is modest (up to ~64-bit)
    if A is not None and B is not None:
        try:
            import sympy.ntheory as nt
            rec_a = int(nt.discrete_log(p, A, g))
            result["a"] = rec_a
            s = pow(B, rec_a, p)
            result["shared_secret"] = s
            result["shared_secret_hex"] = hex(s)
        except Exception:
            pass

    return result


def ecc_point_operation(
    mode: str,
    a: int,
    b: int,
    p: int,
    Px: int,
    Py: int,
    Qx: int | None = None,
    Qy: int | None = None,
    k: int | None = None,
) -> dict[str, int | bool | str | None]:
    """
    Complete Elliptic Curve Point arithmetic on Weierstrass curve y^2 = x^3 + a*x + b (mod p).
    Modes:
      - 'mul' / 'scalar': k * P
      - 'add': P + Q
    """
    P: Point = (Px, Py)
    on_curve_P = is_point_on_curve(P, a, b, p)
    res: dict[str, int | bool | str | None] = {
        "curve": f"y^2 = x^3 + {a}*x + {b} (mod {p})",
        "P": f"({Px}, {Py})",
        "P_on_curve": on_curve_P,
        "result_point": None,
        "is_infinity": False,
    }

    if mode in ("mul", "scalar"):
        if k is None:
            raise ValueError("Scalar k is required for 'mul' mode")
        R = ecc_scalar_mul(k, P, a, p)
        if R is None:
            res["is_infinity"] = True
            res["result_point"] = "O (Point at Infinity)"
        else:
            res["result_point"] = f"({R[0]}, {R[1]})"
            res["Rx"] = R[0]
            res["Ry"] = R[1]
        return res

    elif mode == "add":
        if Qx is None or Qy is None:
            raise ValueError("Qx and Qy are required for 'add' mode")
        Q: Point = (Qx, Qy)
        res["Q"] = f"({Qx}, {Qy})"
        res["Q_on_curve"] = is_point_on_curve(Q, a, b, p)
        R = ecc_point_add(P, Q, a, p)
        if R is None:
            res["is_infinity"] = True
            res["result_point"] = "O (Point at Infinity)"
        else:
            res["result_point"] = f"({R[0]}, {R[1]})"
            res["Rx"] = R[0]
            res["Ry"] = R[1]
        return res

    else:
        raise ValueError(f"Unknown mode '{mode}'. Choose 'mul' or 'add'")
