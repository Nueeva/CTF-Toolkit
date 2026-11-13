"""Univariate Coppersmith small-root attack (Howgrave-Graham).

Recovers a small unknown part ``x`` of a message when most of the message
is known: given ``m = known + x`` with ``|x| < X`` and ``c = m^e mod n``,
solves ``(known + x)^e - c == 0 (mod n)`` for ``x`` via lattice reduction.

Pure Python on top of the toolkit's exact-arithmetic LLL; practical for
small lattice parameters (e <= 5, m = 1..2). For larger instances a
SageMath/fpylll implementation is the right tool.
"""
from __future__ import annotations

from ctf_toolkit.crypto.lattice_lll import lll_reduce


def _poly_mul(a: list[int], b: list[int]) -> list[int]:
    out = [0] * (len(a) + len(b) - 1)
    for i, ca in enumerate(a):
        for j, cb in enumerate(b):
            out[i + j] += ca * cb
    return out


def _poly_pow(a: list[int], e: int) -> list[int]:
    out = [1]
    for _ in range(e):
        out = _poly_mul(out, a)
    return out


def coppersmith_stereotyped(
    n: int,
    e: int,
    c: int,
    known: int,
    x_bound: int,
    m: int = 1,
) -> int | None:
    """Recover ``x`` with ``pow(known + x, e, n) == c`` and ``|x| < x_bound``.

    ``known`` is the known part of the message already shifted into place
    (i.e. the full message is ``known + x``). Returns the full message
    ``known + x``, or None when the lattice does not reveal the root.
    """
    # f(x) = (known + x)^e - c, coefficients low -> high.
    f = _poly_pow([known, 1], e)
    f[0] -= c
    d = e  # degree of f

    # Howgrave-Graham lattice: rows are coefficient vectors of
    #   n^(m-i) * f(x)^i * x^j   for i in 0..m, j in 0..d-1 (f^m only j=0..d-1)
    # scaled by x -> X*x.
    polys: list[list[int]] = []
    for i in range(m + 1):
        fi = _poly_pow(f, i)
        scale = n ** (m - i)
        for j in range(d):
            g = [0] * j + [coef * scale for coef in fi]
            polys.append(g)
    dim = max(len(g) for g in polys)
    basis: list[list[int]] = []
    for g in polys:
        row = []
        for k in range(dim):
            coef = g[k] if k < len(g) else 0
            row.append(coef * (x_bound ** k))
        basis.append(row)

    reduced = lll_reduce(basis)

    # Try each reduced row as a candidate polynomial over the integers.
    import sympy

    x = sympy.symbols("x")
    for row in reduced:
        coeffs: list[int] = []
        ok = True
        for k, val in enumerate(row):
            scale = x_bound ** k
            if val % scale != 0:
                ok = False
                break
            coeffs.append(val // scale)
        if not ok or all(coef == 0 for coef in coeffs):
            continue
        poly = sum(coef * x**k for k, coef in enumerate(coeffs))
        for root in sympy.nroots(poly, n=50, maxsteps=200):
            try:
                xi = int(round(float(root)))
            except (TypeError, ValueError, OverflowError):
                continue
            for cand in (xi - 1, xi, xi + 1):
                if abs(cand) < x_bound and pow(known + cand, e, n) == c:
                    return known + cand
    return None
