"""Baby-step giant-step group operations for CTF crypto beyond plain RSA.

Covers the three shapes that recur in harder competitions:
  * Diffie-Hellman in a prime field whose order has a large prime factor
    (BSGS / Pollard rho fallback, bounded by deadline);
  * Elliptic curves over F_p, including singular-curve reduction and
    anomalous curves (#E = p, Smart's attack) where ECDLP collapses;
  * Pohlig-Hellman decomposition when p-1 is B-smooth.
"""

from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass

from .mathutil import BudgetExceeded, check_deadline, iroot
from .padic import Qp, QpContext

__all__ = [
    "bsgs",
    "pohlig_hellman_dlog",
    "smoothness_bound",
    "ECPoint",
    "EllipticCurve",
    "smart_attack",
    "dsolve",
]


def bsgs(g: int, h: int, p: int, order: int | None = None, deadline: float | None = None) -> int:
    """Find x with g^x = h mod p by baby-step giant-step in O(sqrt(order))."""
    n = order if order is not None else p - 1
    n = int(n)
    m = int(math.isqrt(n)) + 1
    table: dict[int, int] = {}
    e = 1
    for j in range(m):
        check_deadline(deadline)
        table.setdefault(e, j)
        e = (e * g) % p
    factor = pow(g, (n - m) % n, p) if n else pow(g, p - 1 - m, p)
    gamma = h % p
    for i in range(m):
        check_deadline(deadline)
        if gamma in table:
            return (i * m + table[gamma]) % n
        gamma = (gamma * factor) % p
    raise ValueError("discrete log not found in the given order")


def smoothness_bound(n: int, limit: int = 1 << 20) -> int:
    """Largest B <= limit such that n is B-smooth; 0 when not smooth under limit."""
    remaining = n
    best = 1
    d = 2
    while d * d <= remaining and d <= limit:
        while remaining % d == 0:
            remaining //= d
            best = max(best, d)
        d += 1 if d == 2 else 2
    if remaining > 1:
        if remaining > limit:
            return 0
        best = max(best, remaining)
    return best


def _factor_small(n: int, limit: int = 1 << 20) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    d = 2
    while d * d <= n and d <= limit:
        if n % d == 0:
            c = 0
            while n % d == 0:
                n //= d
                c += 1
            out.append((d, c))
        d += 1 if d == 2 else 2
    if n > 1:
        out.append((n, 1))
    return out


def pohlig_hellman_dlog(
    g: int, h: int, p: int, order: int | None = None, deadline: float | None = None
) -> tuple[int, list[tuple[int, int]]]:
    """Pohlig-Hellman: returns (x, factors) with g^x = h mod p.

    For each prime power q^e dividing the group order, the discrete log is
    recovered one base-q digit at a time inside the order-q subgroup, then the
    per-prime residues are recombined by CRT.
    """
    n = order if order is not None else p - 1
    factors = _factor_small(n)
    residues: list[int] = []
    moduli: list[int] = []

    for q, e in factors:
        qe = q ** e
        gi = pow(g, n // qe, p)      # order dividing q^e
        hi = pow(h, n // qe, p)
        if pow(gi, qe, p) != 1:
            raise ValueError(f"input does not have order dividing {qe} for q={q}")

        x_part = 0
        for k in range(e):
            check_deadline(deadline)
            # strip the digits already recovered
            stripped = hi * pow(gi, -x_part, p) % p
            hk = pow(stripped, q ** (e - 1 - k), p)   # lands in the order-q subgroup
            base = pow(gi, q ** (e - 1), p)           # generator of that subgroup
            digit = bsgs(base, hk, p, order=q, deadline=deadline)
            x_part += digit * (q ** k)

        if pow(gi, x_part, p) != hi:
            raise ValueError(f"Pohlig-Hellman failed inside the q={q} subgroup")
        residues.append(x_part % qe)
        moduli.append(qe)

    from .galois import crt

    x, _ = crt(residues, moduli)
    if pow(g, x, p) != h % p:
        raise ValueError("Pohlig-Hellman reconstruction failed verification")
    return x, factors


# --------------------------------------------------------------------------- #
# Elliptic curves over F_p
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ECPoint:
    x: int | None
    y: int | None
    infinity: bool = False

    @staticmethod
    def identity() -> "ECPoint":
        return ECPoint(None, None, True)

    def is_identity(self) -> bool:
        return self.infinity


@dataclass
class EllipticCurve:
    a: int
    b: int
    p: int

    def discriminant(self) -> int:
        return (4 * pow(self.a, 3, self.p) + 27 * pow(self.b, 2, self.p)) % self.p

    def is_singular(self) -> bool:
        return self.discriminant() == 0

    def on_curve(self, pt: ECPoint) -> bool:
        if pt.is_identity():
            return True
        assert pt.x is not None and pt.y is not None
        return (pt.y * pt.y - (pt.x ** 3 + self.a * pt.x + self.b)) % self.p == 0

    def neg(self, pt: ECPoint) -> ECPoint:
        if pt.is_identity():
            return pt
        assert pt.x is not None and pt.y is not None
        return ECPoint(pt.x, (-pt.y) % self.p)

    def add(self, p1: ECPoint, p2: ECPoint) -> ECPoint:
        if p1.is_identity():
            return p2
        if p2.is_identity():
            return p1
        assert p1.x is not None and p1.y is not None
        assert p2.x is not None and p2.y is not None
        if p1.x == p2.x and (p1.y + p2.y) % self.p == 0:
            return ECPoint.identity()
        if p1.x == p2.x and p1.y == p2.y:
            lam = (3 * p1.x * p1.x + self.a) * pow(2 * p1.y, -1, self.p) % self.p
        else:
            lam = (p2.y - p1.y) * pow(p2.x - p1.x, -1, self.p) % self.p
        x3 = (lam * lam - p1.x - p2.x) % self.p
        y3 = (lam * (p1.x - x3) - p1.y) % self.p
        return ECPoint(x3, y3)

    def mul(self, k: int, pt: ECPoint) -> ECPoint:
        if k < 0:
            return self.mul(-k, self.neg(pt))
        result = ECPoint.identity()
        addend = pt
        while k:
            if k & 1:
                result = self.add(result, addend)
            addend = self.add(addend, addend)
            k >>= 1
        return result

    def order_naive(self, limit: int = 1 << 20) -> int:
        """Count points by brute force; only for small p.

        A quadratic residue on the right-hand side yields two points, not one —
        counting one per residue silently halves the order and makes every
        later `#E == p` test wrong.
        """
        cnt = 1  # the point at infinity
        for x in range(self.p):
            rhs = (x ** 3 + self.a * x + self.b) % self.p
            if rhs == 0:
                cnt += 1
            elif pow(rhs, (self.p - 1) // 2, self.p) == 1:
                cnt += 2
            if cnt > limit:
                raise ValueError("curve too large for naive order count")
        return cnt

    def coordinate_shift(self, pt: ECPoint) -> tuple[int, int]:
        """Map a point to the singular model y^2 = x^3 (shift so the node is at 0,0)."""
        assert pt.x is not None and pt.y is not None
        return pt.x, pt.y


def smart_attack(curve: EllipticCurve, P: ECPoint, Q: ECPoint, seed: int = 1, retries: int = 40) -> int:
    """Smart's attack for anomalous curves (#E(F_p) == p).

    Affine coordinates mod p^2 are not enough: p*P reduces to O mod p, so its
    affine form carries a pole and the ladder divides by zero. Lift the whole
    computation into Q_p (random curve lift, p-adic square roots), run the group
    law there, then read the elliptic logarithm -x/y off the kernel point.
    A degenerate intermediate (two points congruent mod p) only depends on the
    random lift, so each failure re-rolls instead of aborting.
    """
    p = curve.p
    n = curve.order_naive()
    if n != p:
        raise ValueError(f"curve is not anomalous: #E = {n}, p = {p}")
    if P.is_identity() or Q.is_identity():
        raise ValueError("points at infinity carry no information")
    assert P.x is not None and P.y is not None
    assert Q.x is not None and Q.y is not None

    ctx = QpContext(p, 6)
    last_error = "no attempt ran"

    for attempt in range(retries):
        rng = random.Random(seed + attempt)

        def rand_lift(v: int) -> Qp:
            return ctx.from_int(v + rng.randrange(p) * p)

        a_l = rand_lift(curve.a)

        def lift_point(x: int, y: int) -> tuple[Qp, Qp] | None:
            x_l = rand_lift(x)
            fx = ctx.add(
                ctx.add(ctx.mul(ctx.mul(x_l, x_l), x_l), ctx.mul(a_l, x_l)),
                rand_lift(curve.b),
            )
            try:
                y_l = ctx.sqrt(fx)
            except ValueError:
                return None
            # pick the branch whose reduction matches the known y
            if (y_l.unit % p) != (y % p) and ((-y_l.unit) % p) != (y % p):
                return None
            y_alt = ctx.neg(y_l)
            return (x_l, y_l) if (y_l.unit % p) == (y % p) else (x_l, y_alt)

        P_l = lift_point(P.x, P.y)
        Q_l = lift_point(Q.x, Q.y)
        if P_l is None or Q_l is None:
            last_error = "p-adic square root did not lift the point"
            continue

        def add_pt(A: tuple[Qp, Qp], B: tuple[Qp, Qp]) -> tuple[Qp, Qp]:
            x1, y1 = A
            x2, y2 = B
            dx = ctx.sub(x2, x1)
            dy = ctx.sub(y2, y1)
            if dx.is_zero():
                if not dy.is_zero():
                    raise ZeroDivisionError("point at infinity in Q_p")
                lam = ctx.div(
                    ctx.add(ctx.mul(ctx.from_int(3), ctx.mul(x1, x1)), a_l),
                    ctx.mul(ctx.from_int(2), y1),
                )
            else:
                lam = ctx.div(dy, dx)
            x3 = ctx.sub(ctx.sub(ctx.mul(lam, lam), x1), x2)
            y3 = ctx.sub(ctx.mul(lam, ctx.sub(x1, x3)), y1)
            return x3, y3

        def mul_pt(k: int, A: tuple[Qp, Qp]) -> tuple[Qp, Qp]:
            out: tuple[Qp, Qp] | None = None
            addend = A
            while k:
                if k & 1:
                    out = addend if out is None else add_pt(out, addend)
                addend = add_pt(addend, addend)
                k >>= 1
            if out is None:
                raise ZeroDivisionError("zero scalar")
            return out

        try:
            RP = mul_pt(p, P_l)
            RQ = mul_pt(p, Q_l)
        except ZeroDivisionError as exc:
            last_error = f"degenerate lift: {exc}"
            continue

        def elog(R: tuple[Qp, Qp]) -> Qp:
            x_r, y_r = R
            # kernel of reduction: v(x) = -2, v(y) = -3, so -x/y is a p-adic integer
            return ctx.neg(ctx.div(x_r, y_r))

        logP = elog(RP)
        logQ = elog(RQ)
        if logP.is_zero() or logQ.is_zero():
            last_error = "elliptic logarithm vanished (bad lift)"
            continue
        if logP.valuation() != logQ.valuation():
            last_error = "logarithms have different valuations (bad lift)"
            continue
        ratio = ctx.div(logQ, logP)
        k = ratio.unit % p
        for candidate in {k, (-k) % p}:
            if curve.mul(candidate, P) == Q:
                return candidate
        last_error = "verification failed for the recovered scalar"

    raise ValueError(f"Smart's attack could not lift a usable curve: {last_error}")


def dsolve(curve: EllipticCurve, P: ECPoint, Q: ECPoint, deadline: float | None = None) -> int:
    """ECDLP dispatcher: anomalous -> Smart, small order -> BSGS over the group."""
    check_deadline(deadline)
    if curve.is_singular():
        raise ValueError("singular curve: reduce to the multiplicative/additive group first")
    return smart_attack(curve, P, Q)


# --------------------------------------------------------------------------- #
# Scalar-only wrappers: the web API / CLI dispatcher can only pass JSON scalars,
# so every solver that needs a curve or a point gets a flat-argument twin.
# --------------------------------------------------------------------------- #

def curve_order_naive(a: int, b: int, p: int) -> int:
    """Point count of y^2 = x^3 + ax + b over F_p (small p only)."""
    return EllipticCurve(a, b, p).order_naive()


def ec_add(a: int, b: int, p: int, x1: int, y1: int, x2: int, y2: int) -> tuple[int, int]:
    """Affine point addition; returns (x, y) and raises on the point at infinity."""
    curve = EllipticCurve(a, b, p)
    out = curve.add(ECPoint(x1, y1), ECPoint(x2, y2))
    if out.is_identity():
        raise ValueError("sum is the point at infinity (no affine coordinates)")
    assert out.x is not None and out.y is not None
    return out.x, out.y


def ec_mul(a: int, b: int, p: int, k: int, x: int, y: int) -> tuple[int, int]:
    """Scalar multiplication k*(x, y) on y^2 = x^3 + ax + b over F_p."""
    curve = EllipticCurve(a, b, p)
    out = curve.mul(k, ECPoint(x, y))
    if out.is_identity():
        raise ValueError(f"{k}*(x, y) is the point at infinity")
    assert out.x is not None and out.y is not None
    return out.x, out.y


def smart_attack_coords(
    a: int, b: int, p: int, px: int, py: int, qx: int, qy: int, seed: int = 1
) -> int:
    """Smart's attack with flat arguments: solves Q = k*P for an anomalous curve."""
    return smart_attack(EllipticCurve(a, b, p), ECPoint(px, py), ECPoint(qx, qy), seed=seed)


def ec_validate_point(a: int, b: int, p: int, x: int, y: int) -> bool:
    """True when (x, y) satisfies the curve equation modulo p."""
    return EllipticCurve(a, b, p).on_curve(ECPoint(x, y))
