from __future__ import annotations

import sympy

from ctf_toolkit.crypto.coppersmith import coppersmith_stereotyped


def test_coppersmith_stereotyped_e3() -> None:
    p = int(sympy.nextprime(2**127 + 12345))
    q = int(sympy.nextprime(2**127 + 987654))
    n = p * q
    e = 3
    prefix = b"flag is CTF{sm"
    suffix = b"1th}"
    msg = prefix + suffix
    m_int = int.from_bytes(msg, "big")
    known = int.from_bytes(prefix, "big") << (8 * len(suffix))
    x_bound = 1 << (8 * len(suffix))
    c = pow(m_int, e, n)
    recovered = coppersmith_stereotyped(n, e, c, known, x_bound, m=1)
    assert recovered == m_int


def test_coppersmith_wrong_bound_returns_none_or_no_false_positive() -> None:
    p = int(sympy.nextprime(2**127 + 999))
    q = int(sympy.nextprime(2**127 + 424242))
    n = p * q
    e = 3
    # Unknown part far above the claimed bound: must not fabricate a message.
    prefix = b"aaaaaaaaaaaaaaaa"
    suffix = b"ZZZZZZZZ"
    msg = prefix + suffix
    m_int = int.from_bytes(msg, "big")
    known = int.from_bytes(prefix, "big") << (8 * len(suffix))
    c = pow(m_int, e, n)
    recovered = coppersmith_stereotyped(n, e, c, known, 1 << 16, m=1)
    assert recovered is None or pow(recovered, e, n) == c
