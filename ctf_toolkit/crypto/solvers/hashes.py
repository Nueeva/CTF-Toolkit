"""Hash lookup and wordlist verification."""

from __future__ import annotations

import hashlib
import re

from ..cascade import Candidate, SolveContext

_ALGS = {
    32: ("md5", hashlib.md5),
    40: ("sha1", hashlib.sha1),
    64: ("sha256", hashlib.sha256),
    128: ("sha512", hashlib.sha512),
}


def solve_hash_lookup(ctx: SolveContext) -> list[Candidate]:
    # Extract candidate hex digest from output
    m = re.search(r"\b([0-9a-fA-F]{32,128})\b", ctx.output_text)
    if not m:
        return []
    target = m.group(1).lower()
    meta = _ALGS.get(len(target))
    if not meta:
        return []
    alg_name, hasher = meta
    # Try fast wordlist / numeric brute for small ranges (0..100000)
    for i in range(100000):
        probe = str(i).encode()
        if hasher(probe).hexdigest() == target:
            return [Candidate(probe, f"hash_numeric_brute[{alg_name}={target[:8]}]")]
    return []


SOLVERS = {
    "hash_lookup": solve_hash_lookup,
}
