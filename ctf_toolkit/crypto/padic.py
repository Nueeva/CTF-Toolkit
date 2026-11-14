"""Fixed-precision p-adic numbers for Smart's attack and p-adic lifting.

A number is stored as `unit * p**exp` where `unit` is an integer modulo
`p**precision` (a p-adic unit when canonical). Arithmetic keeps the exponent
explicit so a value that vanishes modulo p — exactly what happens to `p*P` in
affine coordinates mod p^2 — still divides correctly instead of blowing up.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

__all__ = ["Qp", "QpContext", "padic_from_int", "padic_sqrt"]


@dataclass(frozen=True)
class Qp:
    """`unit * p**exp` with `unit` reduced modulo p**precision."""

    ctx: "QpContext"
    unit: int
    exp: int

    # -- constructors ------------------------------------------------------ #
    @property
    def modulus(self) -> int:
        return self.ctx.modulus

    def is_zero(self) -> bool:
        return self.unit % self.modulus == 0

    def valuation(self) -> int:
        """p-adic valuation; only exact inside the stored precision."""
        if self.is_zero():
            raise ValueError("valuation of zero is infinite")
        return self.exp

    def canonical(self) -> "Qp":
        """Strip factors of p out of the unit so `exp` is the true valuation."""
        u = self.unit % self.modulus
        if u == 0:
            return Qp(self.ctx, 0, self.ctx.precision)
        e = self.exp
        while u % self.ctx.p == 0:
            u //= self.ctx.p
            e += 1
        return Qp(self.ctx, u, e)

    def to_int(self, digits: int = 1) -> int:
        """Lowest `digits` base-p digits of the value, as an integer."""
        if self.exp < 0:
            raise ValueError("negative valuation cannot be flattened to an int")
        return (self.unit % self.ctx.modulus) * (self.ctx.p ** self.exp) % (
            self.ctx.p ** digits
        )

    def unit_mod_p(self) -> int:
        return self.canonical().unit % self.ctx.p

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Qp({self.unit}*{self.ctx.p}^{self.exp})"


class QpContext:
    def __init__(self, p: int, precision: int = 5) -> None:
        if p < 2:
            raise ValueError("p must be prime and >= 2")
        self.p = p
        self.precision = precision
        self.modulus = p ** precision

    def from_int(self, n: int, exp: int = 0) -> Qp:
        return Qp(self, n % self.modulus, exp).canonical()

    def zero(self) -> Qp:
        return Qp(self, 0, self.precision)

    def one(self) -> Qp:
        return Qp(self, 1, 0)

    # -- arithmetic -------------------------------------------------------- #
    def _align(self, a: Qp, b: Qp) -> tuple[int, int, int]:
        e = min(a.exp, b.exp)
        ua = a.unit * self.p ** (a.exp - e) % self.modulus
        ub = b.unit * self.p ** (b.exp - e) % self.modulus
        return ua, ub, e

    def add(self, a: Qp, b: Qp) -> Qp:
        ua, ub, e = self._align(a, b)
        return Qp(self, (ua + ub) % self.modulus, e).canonical()

    def sub(self, a: Qp, b: Qp) -> Qp:
        ua, ub, e = self._align(a, b)
        return Qp(self, (ua - ub) % self.modulus, e).canonical()

    def mul(self, a: Qp, b: Qp) -> Qp:
        return Qp(self, a.unit * b.unit % self.modulus, a.exp + b.exp).canonical()

    def div(self, a: Qp, b: Qp) -> Qp:
        if b.is_zero():
            raise ZeroDivisionError("division by a p-adic zero")
        bb = b.canonical()
        inv = pow(bb.unit % self.modulus, -1, self.modulus)
        return Qp(self, a.unit * inv % self.modulus, a.exp - bb.exp).canonical()

    def neg(self, a: Qp) -> Qp:
        return Qp(self, (-a.unit) % self.modulus, a.exp).canonical()

    def eq(self, a: Qp, b: Qp) -> bool:
        ua, ub, _ = self._align(a, b)
        return ua == ub

    def is_unit(self, a: Qp) -> bool:
        return not a.is_zero() and a.canonical().exp == 0

    # -- square root by digit-by-digit Hensel ------------------------------ #
    def sqrt(self, a: Qp, guess: Optional[int] = None) -> Qp:
        """p-adic square root of a unit, lifted one digit at a time."""
        if a.is_zero():
            return self.zero()
        ac = a.canonical()
        if ac.exp % 2 or ac.exp != 0:
            raise ValueError("sqrt implemented for p-adic units only")
        x = guess if guess is not None else self._sqrt_mod_p(ac.unit % self.p)
        if x is None:
            raise ValueError("argument is not a quadratic residue")
        cur = self.from_int(x % self.p)
        for _ in range(1, self.precision):
            # Newton step: cur <- (cur + a/cur) / 2  in Z/p^k
            k = self.p ** (cur.exp + 1)
            inv_2 = pow(2, -1, self.modulus)
            step = self.mul(self.add(cur, self.div(a, cur)), self.from_int(inv_2))
            cur = self.from_int(step.to_int(self.precision))
            _ = k
        return cur

    def _sqrt_mod_p(self, r: int) -> Optional[int]:
        p = self.p
        if r % p == 0:
            return 0
        if p == 2:
            return r % 2
        if pow(r, (p - 1) // 2, p) != 1:
            return None
        if p % 4 == 3:
            return pow(r, (p + 1) // 4, p)
        # Tonelli-Shanks
        q, s = p - 1, 0
        while q % 2 == 0:
            q //= 2
            s += 1
        z = 2
        while pow(z, (p - 1) // 2, p) != p - 1:
            z += 1
        m, c, t, r_ = s, pow(z, q, p), pow(r, q, p), pow(r, (q + 1) // 2, p)
        while t != 1:
            i, t2 = 0, t
            while t2 != 1:
                t2 = t2 * t2 % p
                i += 1
                if i == m:
                    return None
            b = pow(c, 1 << (m - i - 1), p)
            m, c = i, b * b % p
            t, r_ = t * c % p, r_ * b % p
        return r_


def padic_from_int(ctx: QpContext, n: int, exp: int = 0) -> Qp:
    return ctx.from_int(n, exp)


def padic_sqrt(ctx: QpContext, a: Qp, guess: Optional[int] = None) -> Qp:
    return ctx.sqrt(a, guess)
