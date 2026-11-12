"""Registry of solver functions keyed by the names the tracer emits in `plan`."""

from __future__ import annotations

from typing import Callable

from ..cascade import SolveContext, Candidate

from . import aes, classical, encoding, hashes, poly, rsa, stream, verify, xor

REGISTRY: dict[str, Callable[[SolveContext], list[Candidate]]] = {}
for _mod in (rsa, poly, aes, stream, xor, classical, encoding, hashes, verify):
    REGISTRY.update(getattr(_mod, "SOLVERS", {}))

__all__ = ["REGISTRY"]
