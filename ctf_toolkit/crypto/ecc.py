from __future__ import annotations

from math import isqrt
from ctf_toolkit.utils.math import modinv

Point = tuple[int, int] | None


def ecc_point_add(P: Point, Q: Point, a: int, p: int) -> Point:
    """Add two points P and Q on the short Weierstrass elliptic curve y^2 = x^3 + a*x + b (mod p)."""
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        if y1 % p == 0:
            return None
        lam = ((3 * x1 * x1 + a) * modinv((2 * y1) % p, p)) % p
    else:
        lam = ((y2 - y1) * modinv((x2 - x1) % p, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def ecc_scalar_mul(k: int, P: Point, a: int, p: int) -> Point:
    """Compute scalar multiplication k * P on y^2 = x^3 + a*x + b (mod p) via double-and-add."""
    if k == 0 or P is None:
        return None
    if k < 0:
        P = (P[0], (-P[1]) % p)
        k = -k
    result: Point = None
    addend: Point = P
    while k > 0:
        if k & 1:
            result = ecc_point_add(result, addend, a, p)
        addend = ecc_point_add(addend, addend, a, p)
        k >>= 1
    return result


def ecc_small_subgroup_dlog(
    G: tuple[int, int],
    Q: tuple[int, int],
    a: int,
    p: int,
    bound: int = 65536,
) -> int | None:
    """
    Solve the Elliptic Curve Discrete Logarithm Problem (ECDLP) Q = d * G
    for small subgroup / smooth factors up to `bound` using Baby-Step Giant-Step (BSGS).
    """
    m = isqrt(bound) + 1
    table: dict[Point, int] = {}
    curr: Point = None
    for j in range(m):
        table[curr] = j
        curr = ecc_point_add(curr, G, a, p)

    mG = ecc_scalar_mul(m, G, a, p)
    if mG is None:
        return table.get(Q)
    neg_mG = (mG[0], (-mG[1]) % p)

    gamma: Point = Q
    for i in range(m + 1):
        if gamma in table:
            return i * m + table[gamma]
        gamma = ecc_point_add(gamma, neg_mG, a, p)
    return None


def _proj_add_mod_p2(
    P: tuple[int, int, int],
    Q: tuple[int, int, int],
    a: int,
    b: int,
    p2: int,
) -> tuple[int, int, int]:
    """
    Homogeneous projective addition on Y^2 Z = X^3 + a X Z^2 + b Z^3 (mod p^2)
    using Bosma-Lenstra complete addition formulas so points reducing to O mod p are handled cleanly.
    """
    X1, Y1, Z1 = P
    X2, Y2, Z2 = Q
    if X1 == 0 and Z1 == 0:
        return Q
    if X2 == 0 and Z2 == 0:
        return P

    U1 = (Y2 * Z1) % p2
    U2 = (Y1 * Z2) % p2
    V1 = (X2 * Z1) % p2
    V2 = (X1 * Z2) % p2

    if V1 == V2:
        if U1 != U2 or Y1 == 0:
            return (0, 1, 0)
        # Point doubling
        W = (3 * X1 * X1 + a * Z1 * Z1) % p2
        S = (Y1 * Z1) % p2
        B = (X1 * Y1 * S) % p2
        H = (W * W - 8 * B) % p2
        X3 = (2 * H * S) % p2
        Y3 = (W * (4 * B - H) - 8 * Y1 * Y1 * S * S) % p2
        Z3 = (8 * S * S * S) % p2
        return (X3, Y3, Z3)

    U = (U1 - U2) % p2
    V = (V1 - V2) % p2
    W = (Z1 * Z2) % p2
    A = (U * U * W - V * V * V - 2 * V * V * V2) % p2
    X3 = (V * A) % p2
    Y3 = (U * (V * V * V2 - A) - V * V * V * U2) % p2
    Z3 = (V * V * V * W) % p2
    return (X3, Y3, Z3)


def _proj_mul_mod_p2(
    k: int,
    P: tuple[int, int, int],
    a: int,
    b: int,
    p2: int,
) -> tuple[int, int, int]:
    res = (0, 1, 0)
    addend = P
    while k > 0:
        if k & 1:
            res = _proj_add_mod_p2(res, addend, a, b, p2)
        addend = _proj_add_mod_p2(addend, addend, a, b, p2)
        k >>= 1
    return res


def ecc_smarts_attack(
    G: tuple[int, int],
    Q: tuple[int, int],
    a: int,
    b: int,
    p: int,
) -> int:
    """
    Smart's p-adic elliptic curve logarithm attack for anomalous curves (#E(F_p) == p).
    Lifts G and Q to E(Q_p) mod p^2 in projective space and computes d = log_p(p * Q) / log_p(p * G) mod p.
    """
    p2 = p * p

    def _lift(pt: tuple[int, int], a_lift: int, b_lift: int) -> tuple[int, int, int]:
        x, y = pt
        rhs = (x * x * x + a_lift * x + b_lift - y * y) % p2
        dy = (2 * y) % p
        k = ((rhs // p) * modinv(dy, p)) % p
        return (x, (y + k * p) % p2, 1)

    for b_mod in (b, (b + p) % p2):
        G_lift = _lift(G, a, b_mod)
        Q_lift = _lift(Q, a, b_mod)
        # Compute (p - 1)*G_lift + G_lift in projective coordinates mod p^2
        p_minus_1_G = _proj_mul_mod_p2(p - 1, G_lift, a, b_mod, p2)
        p_minus_1_Q = _proj_mul_mod_p2(p - 1, Q_lift, a, b_mod, p2)

        # In affine mod p^2 before the final addition, (p-1)*P = (x', y') with x' == x mod p, y' == -y mod p
        # Formal group parameter for P + (p-1)*P uses slope lambda = (y_2 - y_1) / (x_2 - x_1)
        inv_zG = modinv(p_minus_1_G[2] // (p if p_minus_1_G[2] % p == 0 else 1), p2)
        inv_zQ = modinv(p_minus_1_Q[2] // (p if p_minus_1_Q[2] % p == 0 else 1), p2)
        xG2 = (p_minus_1_G[0] * inv_zG) % p2
        yG2 = (p_minus_1_G[1] * inv_zG) % p2
        xQ2 = (p_minus_1_Q[0] * inv_zQ) % p2
        yQ2 = (p_minus_1_Q[1] * inv_zQ) % p2

        dx_G = ((xG2 - G_lift[0]) % p2) // p
        dy_G = (yG2 - G_lift[1]) % p
        dx_Q = ((xQ2 - Q_lift[0]) % p2) // p
        dy_Q = (yQ2 - Q_lift[1]) % p

        if dx_G % p != 0 and dy_G % p != 0 and dy_Q % p != 0:
            log_G = (dx_G * modinv(dy_G, p)) % p
            log_Q = (dx_Q * modinv(dy_Q, p)) % p
            if log_G % p != 0:
                d = (log_Q * modinv(log_G, p)) % p
                if ecc_scalar_mul(d, G, a, p) == Q:
                    return d

    # Fallback to BSGS when p is small
    if p <= 1_000_000:
        d_bsgs = ecc_small_subgroup_dlog(G, Q, a, p, bound=p + 1)
        if d_bsgs is not None:
            return d_bsgs

    raise ValueError("Curve does not appear to be anomalous or lift failed")
