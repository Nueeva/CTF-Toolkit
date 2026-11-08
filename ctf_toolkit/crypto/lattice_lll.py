from __future__ import annotations

from fractions import Fraction


def _dot(u: list[int | Fraction], v: list[int | Fraction]) -> int | Fraction:
    return sum(x * y for x, y in zip(u, v))


def gauss_reduce_2d(v1: list[int], v2: list[int]) -> tuple[list[int], list[int]]:
    """Lagrange-Gauss 2D lattice basis reduction returning the shortest orthogonalized basis vectors."""
    u = list(v1)
    v = list(v2)
    while True:
        if _dot(v, v) < _dot(u, u):
            u, v = v, u
        uu = _dot(u, u)
        if uu == 0:
            break
        mu = round(_dot(u, v) / uu)
        if mu == 0:
            break
        v = [vi - mu * ui for ui, vi in zip(u, v)]
    return u, v


def lll_reduce(basis: list[list[int]], delta: float = 0.75) -> list[list[int]]:
    """
    Pure-Python exact rational Lenstra-Lenstra-Lovasz (LLL) lattice basis reduction algorithm.
    Useful for Hidden Number Problem (HNP), truncated LCG recovery, subset-sum knapsacks, and small roots.
    """
    n = len(basis)
    if n == 0:
        return []
    m = len(basis[0])
    B = [[ int(x) for x in row ] for row in basis]
    delta_f = Fraction(delta).limit_denominator(1000)

    def gram_schmidt() -> tuple[list[list[Fraction]], list[list[Fraction]], list[Fraction]]:
        B_star: list[list[Fraction]] = []
        mu: list[list[Fraction]] = [[Fraction(0)] * n for _ in range(n)]
        B_norm: list[Fraction] = []
        for i in range(n):
            vi = [Fraction(x) for x in B[i]]
            for j in range(i):
                denom = B_norm[j]
                mu_ij = Fraction(_dot(B[i], B_star[j]), denom) if denom != 0 else Fraction(0)
                mu[i][j] = mu_ij
                vi = [vi[k] - mu_ij * B_star[j][k] for k in range(m)]
            B_star.append(vi)
            B_norm.append(Fraction(_dot(vi, vi)))
        return B_star, mu, B_norm

    B_star, mu, B_norm = gram_schmidt()
    k = 1
    while k < n:
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > Fraction(1, 2):
                q = int(round(mu[k][j]))
                B[k] = [B[k][idx] - q * B[j][idx] for idx in range(m)]
                B_star, mu, B_norm = gram_schmidt()

        if B_norm[k] >= (delta_f - mu[k][k - 1] * mu[k][k - 1]) * B_norm[k - 1]:
            k += 1
        else:
            B[k], B[k - 1] = B[k - 1], B[k]
            B_star, mu, B_norm = gram_schmidt()
            k = max(k - 1, 1)

    return B


def solve_truncated_lcg_2step(
    y0: int,
    y1: int,
    a: int,
    c: int,
    m: int,
    shift: int,
) -> int:
    """
    Recover full internal state x0 of a truncated LCG where y_i = x_i >> shift
    and x_{i+1} = (a * x_i + c) mod m using 2D lattice reduction.
    """
    scale = 1 << shift
    base_x0 = y0 << shift
    base_x1 = y1 << shift
    # We want small (e0, e1) in [0, scale) such that a*(base_x0 + e0) + c - (base_x1 + e1) = 0 mod m
    target = (base_x1 - a * base_x0 - c) % m
    basis = [
        [m, 0],
        [a, 1],
    ]
    u, v = gauss_reduce_2d(basis[0], basis[1])
    # Brute-force small unknown low bits when shift <= 20, or use lattice vector
    if shift <= 20:
        for e0 in range(scale):
            x0_cand = base_x0 + e0
            x1_cand = (a * x0_cand + c) % m
            if (x1_cand >> shift) == y1:
                return x0_cand
    # Lattice inhomogeneous closest vector approximation
    det = u[0] * v[1] - u[1] * v[0]
    if det != 0:
        k1 = round((target * v[1]) / det)
        k2 = round((-target * u[1]) / det)
        e0_approx = target * 0 - (k1 * u[0] + k2 * v[0])
        for delta_e in range(-256, 257):
            e0 = (e0_approx + delta_e) % scale
            x0_cand = base_x0 + e0
            if (((a * x0_cand + c) % m) >> shift) == y1:
                return x0_cand
    return base_x0
