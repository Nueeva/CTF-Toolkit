from __future__ import annotations

from ctf_toolkit.crypto.auto_solver import extract_flag, solve_crypto_task


def solve_challenge_text(desc: str) -> str | None:
    """Unified automated challenge solver combining crypto heuristics and flag extraction."""
    return solve_crypto_task(desc)
