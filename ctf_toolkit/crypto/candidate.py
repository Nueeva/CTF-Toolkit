"""Candidate acceptance for auto-solver branches.

Solver branches must never fabricate a flag format (e.g. wrapping a decoded
word in some event's ``PREFIX{...}``). A decoded result is accepted when it
either contains a flag matching a known/configured template, or is plausible
plaintext on its own (printable, non-trivial). Otherwise the branch must fall
through and let other solvers try.
"""
from __future__ import annotations

from ctf_toolkit.utils.flag_manager import get_flag_manager


def accept_candidate(decoded: str | bytes | None) -> str | None:
    """Return the flag or plausible plaintext in ``decoded``, else None."""
    if decoded is None:
        return None
    if isinstance(decoded, bytes):
        flag = get_flag_manager().find_first_flag(decoded)
        if flag:
            return flag
        try:
            text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            return None
    else:
        text = decoded
        flag = get_flag_manager().find_first_flag(text)
        if flag:
            return flag
    t = text.strip()
    if len(t) < 3:
        return None
    printable = sum(1 for ch in t if ch.isprintable())
    if printable / len(t) < 0.95:
        return None
    return t


def flag_prefixes() -> list[str]:
    """Literal flag prefixes (e.g. ``GETSFLAG{``) from all known templates.

    Used to build known-plaintext cribs generically instead of hardcoding a
    single event's prefix.
    """
    import re as _re

    prefixes: list[str] = []
    for tmpl in get_flag_manager().templates:
        m = _re.search(r"([A-Za-z][A-Za-z0-9]{1,30})\\\{", tmpl.get("pattern", ""))
        if m:
            cand = m.group(1) + "{"
            if cand not in prefixes:
                prefixes.append(cand)
    return prefixes
