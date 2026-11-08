from __future__ import annotations

from ctf_toolkit.binex.pwn_tools import build_format_string_probe


def leak_stack_offsets(num_words: int = 10, offset_start: int = 1) -> str:
    """Generate positional format string probes to dump stack memory (%1$p.%2$p...)."""
    return build_format_string_probe(num_words=num_words, offset_start=offset_start)


__all__ = ["leak_stack_offsets"]
