"""RSA solvers: factor-first, then exponent pathologies, then multi-sample attacks.

Ordering inside the module matters only for readability; the tracer supplies the
run order. Each solver returns decrypted candidates in the encoding variants a
CTF author plausibly used, so the cascade can match a flag without guessing.
"""

from __future__ import annotations

import math
from typing import Iterable

from ..cascade import Candidate, SolveContext
from ..mathutil import (
    BudgetExceeded,
    bytes_to_long,
    candidate_texts,
    check_deadline,
    factor_integer,
    fermat_factor,
    iroot,
    is_probable_prime,
    long_to_bytes,
    modinv,
    pollard_pm1,
    trial_division,
    wiener_attack,
)


def _triplet(ctx: SolveContext) -> tuple[int, int, int] | None:
    p = ctx.params
    n, e, c = p.get("n"), p.get("e"), p.get("c")
    # If e is not in params, check trace report params
    if e is None and ctx.report.get("trace"):
        tr_params = ctx.report["trace"].get("params", {})
        e = tr_params.get("e")
    if not (isinstance(n, int) and isinstance(c, int)):
        return None
    if e is None:
        e = 65537
    if not isinstance(e, int):
        return None
    return n, e, c


def _decrypt_variants(n: int, d: int, c: int, tag: str) -> list[Candidate]:
    m = pow(c, d, n)
    out: list[Candidate] = []
    for label, blob in candidate_texts(m):
        out.append(Candidate(blob, f"{tag}: m=pow(c,d,n) [{label}]"))
    # Some authors pad the message with a fixed prefix; strip non-printable edges.
    raw = long_to_bytes(m)
    stripped = raw.lstrip(b"\x00")
    if stripped != raw:
        out.append(Candidate(stripped, f"{tag}: m stripped of leading zero bytes"))
    return out


def solve_shared_prime(ctx: SolveContext) -> list[Candidate]:
    """Two moduli sharing a factor -> gcd, no factoring needed."""
    samples = ctx.report.get("samples") or []
    moduli = [s["n"] for s in samples if s.get("n")]
    if "n" in ctx.params:
        moduli.append(ctx.params["n"])
    out: list[Candidate] = []
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            g = math.gcd(moduli[i], moduli[j])
            if 1 < g < max(moduli[i], moduli[j]):
                ctx.log.append(f"  shared factor between sample {i} and {j}: {g.bit_length()} bits")
                for sample in samples:
                    if sample.get("n") and sample["n"] % g == 0:
                        p = g
                        q = sample["n"] // p
                        d = modinv(sample["e"], (p - 1) * (q - 1))
                        out.extend(_decrypt_variants(sample["n"], d, sample["c"], f"shared-prime[{i},{j}]"))
                return out
    return out


def solve_small_factor(ctx: SolveContext) -> list[Candidate]:
    t = _triplet(ctx)
    if not t:
        return []
    n, e, c = t
    f = trial_division(n, 200_000, ctx.deadline)
    if not f or not (1 < f < n):
        return []
    p, q = f, n // f
    d = modinv(e, (p - 1) * (q - 1) if is_probable_prime(p) and is_probable_prime(q) else _phi_from_pair(p, q))
    ctx.log.append(f"  small factor {p} ({p.bit_length()} bits)")
    return _decrypt_variants(n, d, c, "small-factor")


def solve_fermat(ctx: SolveContext) -> list[Candidate]:
    t = _triplet(ctx)
    if not t:
        return []
    n, e, c = t
    got = fermat_factor(n, max_iter=2_000_000, deadline=ctx.deadline)
    if not got:
        return []
    p, q = got
    ctx.log.append(f"  fermat delta p-q = {abs(p - q)}")
    d = modinv(e, _phi_from_pair(p, q))
    return _decrypt_variants(n, d, c, "fermat")


def solve_pollard_pm1(ctx: SolveContext) -> list[Candidate]:
    t = _triplet(ctx)
    if not t:
        return []
    n, e, c = t
    f = pollard_pm1(n, bound=100_000, deadline=ctx.deadline)
    if not f:
        return []
    p, q = f, n // f
    d = modinv(e, _phi_from_pair(p, q))
    return _decrypt_variants(n, d, c, "pollard-p-1")


def solve_factor_auto(ctx: SolveContext) -> list[Candidate]:
    t = _triplet(ctx)
    if not t:
        return []
    n, e, c = t
    p, q = factor_integer(n, ctx.deadline)
    d = modinv(e, _phi_from_pair(p, q))
    return _decrypt_variants(n, d, c, "factor-auto")


def solve_small_e_root(ctx: SolveContext) -> list[Candidate]:
    """m^e < n means the ciphertext is an exact e-th power."""
    t = _triplet(ctx)
    if not t:
        return []
    n, e, c = t
    if not isinstance(e, int) or e > 11 or e < 2:
        return []
    m, exact = iroot(c, e)
    if not exact:
        ctx.log.append(f"  e={e}: ciphertext is not an exact {e}-th power")
        return []
    out = [Candidate(blob, f"small-e-root[{e}]: exact integer {e}-th root")
           for _, blob in candidate_texts(m)]
    # also cover m + k*n for small k (stereotyped message wrapped once)
    for k in range(1, 4):
        mk, ok = iroot(c + k * n, e)
        if ok:
            out.extend(Candidate(blob, f"small-e-root[{e}]: root of c+{k}n") for _, blob in candidate_texts(mk))
    return out


def solve_wiener(ctx: SolveContext) -> list[Candidate]:
    t = _triplet(ctx)
    if not t:
        return []
    n, e, c = t
    d = wiener_attack(e, n)
    if not d:
        return []
    ctx.log.append(f"  wiener recovered d ({d.bit_length()} bits)")
    return _decrypt_variants(n, d, c, "wiener")


def solve_common_modulus(ctx: SolveContext) -> list[Candidate]:
    """Same n, different e, same plaintext -> Bezout on the exponents."""
    samples = [s for s in (ctx.report.get("samples") or []) if s.get("n")]
    if len(samples) < 2:
        return []
    out: list[Candidate] = []
    for i in range(len(samples)):
        for j in range(i + 1, len(samples)):
            a, b = samples[i], samples[j]
            if a["n"] != b["n"]:
                continue
            g, u, v = _egcd(a["e"], b["e"])
            if g != 1:
                continue
            m = (pow(a["c"], u, a["n"]) * pow(b["c"], v, b["n"])) % a["n"]
            out.extend(Candidate(blob, f"common-modulus[{i},{j}]") for _, blob in candidate_texts(m))
    return out


def solve_hastad(ctx: SolveContext) -> list[Candidate]:
    """Same small e, pairwise coprime moduli -> CRT then exact root."""
    samples = [s for s in (ctx.report.get("samples") or []) if s.get("n")]
    if len(samples) < 2:
        return []
    e = samples[0]["e"]
    if not isinstance(e, int) or e < 2 or e > 11:
        return []
    if any(s["e"] != e for s in samples):
        return []
    if len(samples) < e:
        ctx.log.append(f"  hastad needs {e} samples, have {len(samples)}")
        return []
    mods = [s["n"] for s in samples[:e]]
    total = math.prod(mods)
    acc = 0
    for s, m_i in zip(samples[:e], mods):
        partial = total // m_i
        acc = (acc + s["c"] * modinv(partial, m_i) * partial) % total
    root, exact = iroot(acc, e)
    if not exact:
        return []
    return [Candidate(blob, f"hastad[e={e}]: CRT + integer root") for _, blob in candidate_texts(root)]


def _phi_from_pair(p: int, q: int) -> int:
    return (p - 1) * (q - 1)


def _egcd(a: int, b: int) -> tuple[int, int, int]:
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q = a // b
        a, b = b, a - q * b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def solve_given_factors(ctx: SolveContext) -> list[Candidate]:
    """Both primes handed over: straight private-key derivation."""
    p = ctx.params.get("p")
    q = ctx.params.get("q")
    t = _triplet(ctx)
    if not t or not isinstance(p, int) or not isinstance(q, int):
        return []
    n, e, c = t
    if p * q != n:
        ctx.log.append("  given p,q do not multiply to n; using p*q as modulus")
        n = p * q
    d = modinv(e, _phi_from_pair(p, q))
    return _decrypt_variants(n, d, c, "given-factors")


def solve_phi_leak(ctx: SolveContext) -> list[Candidate]:
    """Totient leaked: n - phi + 1 gives p + q, so p,q are roots of x^2 - sx + n."""
    t = _triplet(ctx)
    phi = ctx.params.get("phi")
    if not t or not isinstance(phi, int):
        return []
    n, e, c = t
    s = n - phi + 1
    disc = s * s - 4 * n
    if disc < 0:
        return []
    root, exact = iroot(disc, 2)
    if not exact:
        return []
    p = (s + root) // 2
    q = (s - root) // 2
    if p * q != n:
        return []
    d = modinv(e, phi)
    return _decrypt_variants(n, d, c, "phi-leak")


SOLVERS = {
    "rsa_shared_prime": solve_shared_prime,
    "rsa_small_factor_trial": solve_small_factor,
    "rsa_fermat": solve_fermat,
    "rsa_pollard_pm1": solve_pollard_pm1,
    "rsa_factor_auto": solve_factor_auto,
    "rsa_small_e_root": solve_small_e_root,
    "rsa_wiener": solve_wiener,
    "rsa_common_modulus": solve_common_modulus,
    "rsa_hastad": solve_hastad,
    "rsa_given_factors": solve_given_factors,
    "rsa_phi_leak": solve_phi_leak,
}
