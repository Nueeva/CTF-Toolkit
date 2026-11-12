"""Encoding-peel solver: strip stacked encodings until text or a flag appears."""

from __future__ import annotations

import base64
import binascii
import codecs
import re
from urllib.parse import unquote

from ..ast_tracer import extract_bytes_constants
from ..cascade import Candidate, SolveContext

MAX_DEPTH = 6
_EDGE = " \t\r\n\"'`"


def _layer_once(text: str) -> list[tuple[str, str]]:
    """Every single decoding that changes the text, with its label."""
    out: list[tuple[str, str]] = []
    stripped = text.strip(_EDGE)
    if not stripped:
        return out

    candidates: list[tuple[str, str]] = []
    if re.fullmatch(r"[0-9a-fA-F\s]+", stripped) and len(stripped.replace(" ", "")) % 2 == 0:
        try:
            candidates.append(("hex", bytes.fromhex(re.sub(r"\s+", "", stripped)).decode("latin-1")))
        except ValueError:
            pass
    if re.fullmatch(r"[A-Za-z0-9+/\s]*={0,2}", stripped) and len(re.sub(r"\s+", "", stripped)) % 4 == 0:
        try:
            candidates.append(("base64", base64.b64decode(re.sub(r"\s+", "", stripped)).decode("latin-1")))
        except (binascii.Error, ValueError):
            pass
    if re.fullmatch(r"[A-Z2-7=\s]+", stripped) and len(re.sub(r"\s+", "", stripped)) >= 8:
        try:
            padded = re.sub(r"\s+", "", stripped)
            padded += "=" * (-len(padded) % 8)
            candidates.append(("base32", base64.b32decode(padded).decode("latin-1")))
        except (binascii.Error, ValueError):
            pass
    if re.fullmatch(r"[!-u\s]{8,}", stripped):
        try:
            candidates.append(("base85", base64.a85decode(re.sub(r"\s+", "", stripped)).decode("latin-1")))
        except (binascii.Error, ValueError):
            pass
    if "%" in stripped:
        unquoted = unquote(stripped)
        if unquoted != stripped:
            candidates.append(("url", unquoted))
    if re.search(r"[A-Za-z]", stripped):
        candidates.append(("rot13", codecs.decode(stripped, "rot13")))
        candidates.append(("reverse", stripped[::-1]))

    for label, value in candidates:
        if value and value != stripped and "\ufffd" not in value:
            out.append((label, value))
    return out


def solve_encoding_peel(ctx: SolveContext) -> list[Candidate]:
    seeds = [ctx.output_text] if ctx.output_text else []
    seeds += [b.decode("latin-1") for _, b in extract_bytes_constants(ctx.source_text)]
    if not seeds:
        return []

    out: list[Candidate] = []
    frontier: list[tuple[str, str, list[str]]] = [(s, s, []) for s in seeds]
    seen: set[str] = set()

    for _depth in range(MAX_DEPTH):
        nxt: list[tuple[str, str, list[str]]] = []
        for _seed, current, trail in frontier:
            for label, value in _layer_once(current):
                if value in seen:
                    continue
                seen.add(value)
                path = trail + [label]
                out.append(Candidate(value.encode("latin-1"), "peel:" + "->".join(path)))
                nxt.append((_seed, value, path))
        if not nxt:
            break
        frontier = nxt[:24]
    return out


SOLVERS = {
    "encoding_peel": solve_encoding_peel,
}