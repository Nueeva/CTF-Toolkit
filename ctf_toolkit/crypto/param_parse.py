"""Generic challenge-parameter parser.

CTF challenge texts write parameters in many shapes::

    p = 12345            p: 12345            "p": 12345,
    n = 0xDEADBEEF       c=98765             N1 = 111  N2 = 222
    ct(hex) = ab12cd     key: 001122aabb

The auto solver's hand-written regexes historically only understood
``name = <decimal>``. This module parses all of the shapes above into a
canonical prelude of ``name = <decimal>`` / ``name(hex) = <hex>`` lines that
can be prepended to the challenge text so existing solver branches fire
regardless of the source formatting.
"""
from __future__ import annotations

import re

_NAME = r"[A-Za-z_][A-Za-z0-9_]*"
_INT_PAIR = re.compile(
    r'"?(' + _NAME + r')"?\s*[:=]\s*(0[xX][0-9a-fA-F]+|0[bB][01]+|[0-9]{2,})'
)
# Well-known parameter names may legitimately hold single-digit values (e = 3).
_SMALL_VALUE_NAMES = {"p", "q", "n", "e", "c", "d", "r", "s", "g", "a", "b", "x", "y", "k"}
_INT_PAIR_SMALL = re.compile(
    r'"?(' + _NAME + r')"?\s*[:=]\s*(0[xX][0-9a-fA-F]+|0[bB][01]+|[0-9])\b'
)
_HEX_LABELS = {"key", "iv", "nonce", "tag", "ct", "ciphertext", "c"}
_HEX_PAIR = re.compile(
    r'"?(' + _NAME + r')(?:\(hex\))?"?\s*[:=]\s*(?:0[xX])?([0-9a-fA-F]{8,})'
)
_INDEXED = re.compile(r"^(.*?)[_ ]?(\d+)$")


def _base_and_index(name: str) -> tuple[str, int]:
    m = _INDEXED.match(name)
    if m and m.group(1):
        return m.group(1).lower(), int(m.group(2))
    return name.lower(), 0


def parse_int_params(text: str) -> dict[str, list[int]]:
    """Parse integer parameters into {base_name: [values in index order]}.

    Indexed names (``n1``, ``N2``, ``c_3``) collapse under their base name.
    Values may be decimal, ``0x`` hex, or ``0b`` binary.
    """
    found: dict[str, list[tuple[int, int, int]]] = {}
    matches = list(_INT_PAIR.finditer(text))
    matches += [
        m
        for m in _INT_PAIR_SMALL.finditer(text)
        if _base_and_index(m.group(1))[0] in _SMALL_VALUE_NAMES
    ]
    for pos, m in enumerate(matches):
        raw = m.group(2)
        try:
            value = int(raw, 0)
        except ValueError:
            continue
        base, idx = _base_and_index(m.group(1))
        found.setdefault(base, []).append((idx, pos, value))
    out: dict[str, list[int]] = {}
    for base, items in found.items():
        items.sort(key=lambda t: (t[0], t[1]))
        values = [v for _, _, v in items]
        # Drop exact duplicate re-statements of a single value.
        if len(values) > 1 and len(set(values)) == 1:
            values = values[:1]
        out[base] = values
    return out


def parse_hex_params(text: str) -> dict[str, str]:
    """Parse labelled hex blobs (key/iv/nonce/tag/ct/ciphertext) to hex strings."""
    out: dict[str, str] = {}
    for m in _HEX_PAIR.finditer(text):
        label = m.group(1).lower()
        if label not in _HEX_LABELS:
            continue
        hexval = m.group(2).lower()
        if len(hexval) % 2 != 0:
            continue
        # A pure-decimal value is an integer parameter, not a hex blob.
        if hexval.isdigit():
            continue
        out.setdefault(label, hexval)
    return out


def canonical_prelude(text: str) -> str:
    """Build canonical ``name = value`` lines from whatever shape ``text`` uses.

    Returns an empty string when nothing parseable is found. Single values are
    emitted under their base name; multiple indexed values as ``name1``,
    ``name2``, ... Labelled hex blobs are emitted as ``name(hex) = ...``.
    """
    lines: list[str] = []
    for base, values in parse_int_params(text).items():
        if len(values) == 1:
            lines.append(f"{base} = {values[0]}")
        else:
            for i, v in enumerate(values, start=1):
                lines.append(f"{base}{i} = {v}")
    for label, hexval in parse_hex_params(text).items():
        # No space before '=': the legacy branch regexes expect `ct(hex)=...`.
        lines.append(f"{label}(hex)={hexval}")
    return "\n".join(lines) + ("\n" if lines else "")
