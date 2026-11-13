"""Private-key recovery from nonce reuse in ECDSA, DSA, and ElGamal signatures.

"Two signatures, same r" is one of the most common signature CTF patterns:
when a signer reuses the ephemeral nonce ``k`` for two different messages,
the two signature equations become a linear system that exposes the private
key with nothing more than modular arithmetic.  No curve point operations
are needed -- the recovery only uses the published ``(r, s, z)`` values and
the group order.

Public interface:

- :func:`ecdsa_recover_reused_nonce`   -- ECDSA over a group of order ``n``.
- :func:`dsa_recover_reused_nonce`     -- DSA over a subgroup of order ``q``.
- :func:`elgamal_sig_recover_reused_nonce` -- ElGamal signatures mod ``p``.
- :func:`ecdsa_recover_from_signatures` -- dict-based ECDSA convenience wrapper.

Pure standard library.
"""

from __future__ import annotations

from math import gcd


def _ecdsa_dsa_recover(
    r: int,
    s1: int,
    s2: int,
    z1: int,
    z2: int,
    order: int,
) -> int:
    """Shared ECDSA/DSA algebra.

    Signing: ``s = k^-1 * (z + r*d) mod order`` with the same ``k`` (hence
    the same ``r``) for both messages.  Subtracting the two equations gives
    ``k = (z1 - z2) / (s1 - s2) mod order`` and then
    ``d = (s1*k - z1) / r mod order``.
    """
    if order <= 1:
        raise ValueError("group order must be greater than 1")
    r %= order
    s1 %= order
    s2 %= order
    z1 %= order
    z2 %= order
    if s1 == s2:
        raise ValueError(
            "s1 == s2 (mod order): the two signatures carry no information "
            "about the nonce (identical signatures or z1 == z2)"
        )
    if r == 0:
        raise ValueError("r must be non-zero modulo the group order")
    k = ((z1 - z2) * pow(s1 - s2, -1, order)) % order
    d = ((s1 * k - z1) * pow(r, -1, order)) % order
    return d


def ecdsa_recover_reused_nonce(
    r: int,
    s1: int,
    s2: int,
    z1: int,
    z2: int,
    order: int,
) -> int:
    """Recover an ECDSA private key ``d`` from two signatures sharing a nonce.

    ``r`` is the shared r component, ``s1``/``s2`` the s components, and
    ``z1``/``z2`` the integer message hashes (already reduced mod ``order``).
    Raises :class:`ValueError` when ``s1 == s2 mod order``.
    """
    return _ecdsa_dsa_recover(r, s1, s2, z1, z2, order)


def dsa_recover_reused_nonce(
    r: int,
    s1: int,
    s2: int,
    z1: int,
    z2: int,
    q: int,
) -> int:
    """Recover a DSA private key ``x`` from two signatures sharing a nonce.

    Identical algebra to ECDSA, with the DSA subgroup order ``q`` in place
    of the curve order.  Raises :class:`ValueError` when ``s1 == s2 mod q``.
    """
    return _ecdsa_dsa_recover(r, s1, s2, z1, z2, q)


def _linear_congruence_solutions(a: int, b: int, m: int) -> list[int]:
    """Return all ``x`` in ``range(m)`` with ``a*x == b (mod m)``.

    The solution set is empty when ``gcd(a, m)`` does not divide ``b``;
    otherwise it contains exactly ``gcd(a, m)`` residues.
    """
    a %= m
    b %= m
    g = gcd(a, m)
    if b % g != 0:
        return []
    a_red, b_red, m_red = a // g, b // g, m // g
    x0 = (b_red * pow(a_red, -1, m_red)) % m_red
    return [x0 + t * m_red for t in range(g)]


def elgamal_sig_recover_reused_nonce(
    r: int,
    s1: int,
    s2: int,
    z1: int,
    z2: int,
    p: int,
) -> int:
    """Recover an ElGamal signature private key ``x`` from a reused nonce.

    ElGamal signatures over the mod-``p`` group satisfy
    ``s = k^-1 * (z - x*r) mod (p - 1)``.  Reusing ``k`` (same ``r``) gives
    the linear congruence ``(s1 - s2) * k == z1 - z2 (mod p - 1)`` for the
    nonce, and ``r * x == z1 - s1*k (mod p - 1)`` for the key.  Because
    ``p - 1`` is composite, neither congruence is guaranteed a unique
    solution: every candidate pair is checked against the second signature
    equation and the unique consistent ``x`` is returned.

    Raises :class:`ValueError` when no candidate is consistent (the inputs
    are not a genuine reused-nonce pair) or the data carries no information.
    """
    m = p - 1
    if m <= 1:
        raise ValueError("p must be greater than 2")
    r %= p
    s1 %= m
    s2 %= m
    z1 %= m
    z2 %= m
    if s1 == s2:
        raise ValueError(
            "s1 == s2 (mod p-1): the two signatures carry no information "
            "about the nonce"
        )

    k_candidates = _linear_congruence_solutions(s1 - s2, z1 - z2, m)
    if not k_candidates:
        raise ValueError(
            "no nonce satisfies (s1 - s2) * k == z1 - z2 (mod p-1); "
            "the signatures are inconsistent with a reused nonce"
        )

    consistent: set[int] = set()
    for k in k_candidates:
        if k == 0:
            continue  # k = 0 is never a valid signing nonce
        # r * x == z1 - s1 * k (mod p-1)
        for x in _linear_congruence_solutions(r, z1 - s1 * k, m):
            # Verify against the second signature: s2 * k == z2 - x * r.
            if (s2 * k - (z2 - x * r)) % m == 0:
                consistent.add(x)

    if not consistent:
        raise ValueError(
            "no private key is consistent with both signatures"
        )
    if len(consistent) > 1:
        raise ValueError(
            "reused-nonce data does not determine a unique private key: "
            f"{len(consistent)} candidates satisfy both signatures"
        )
    return consistent.pop()


def ecdsa_recover_from_signatures(
    sig1: dict,
    sig2: dict,
    order: int,
) -> int | None:
    """Convenience wrapper: recover an ECDSA key from two signature dicts.

    Each dict must provide ``"r"``, ``"s"`` and ``"z"`` (the integer message
    hash).  Returns ``None`` when the r values differ (no nonce reuse);
    otherwise returns the recovered private key.  Propagates
    :class:`ValueError` from :func:`ecdsa_recover_reused_nonce` for a
    degenerate pair with equal s values.
    """
    if sig1["r"] != sig2["r"]:
        return None
    return ecdsa_recover_reused_nonce(
        sig1["r"], sig1["s"], sig2["s"], sig1["z"], sig2["z"], order
    )
