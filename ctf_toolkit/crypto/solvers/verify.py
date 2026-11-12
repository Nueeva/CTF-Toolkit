"""Final pass solvers: raw regex flag scan and direct output checks."""

from __future__ import annotations

import base64
import binascii

from ..cascade import Candidate, SolveContext


def solve_flag_pattern_scan(ctx: SolveContext) -> list[Candidate]:
    """Scan the raw outputs and decoded encodings directly for the flag."""
    out: list[Candidate] = []
    # If the output text has a cipher/encoding marker, do not emit the raw
    # ciphertext as a flag candidate just because it happens to carry braces.
    raw_has_math = (
        any(k in ctx.output_text.lower() for k in ("ciphertext", "enc", "mod", "ct ="))
        or bool(ctx.report.get("script"))
    )
    if ctx.output_bytes and not raw_has_math:
        out.append(Candidate(ctx.output_bytes, "raw_output_bytes"))
    if ctx.output_text and not raw_has_math:
        out.append(Candidate(ctx.output_text.encode("utf-8", "replace"), "raw_output_text"))
        # If output is valid hex or base64, peel one layer
        clean = ctx.output_text.strip()
        try:
            b_hex = bytes.fromhex(clean)
            out.append(Candidate(b_hex, "peeled_hex"))
        except ValueError:
            pass
        try:
            b_b64 = base64.b64decode(clean)
            out.append(Candidate(b_b64, "peeled_base64"))
        except (binascii.Error, ValueError):
            pass
    return out


SOLVERS = {
    "flag_pattern_scan": solve_flag_pattern_scan,
}
