"""Ordered solver cascade: take a tracer report, run solvers, stop at first flag.

The tracer decides the order (`report["plan"]`); this module only dispatches and
verifies. A solver is a function `solve(ctx) -> list[Candidate]`; it may raise
`BudgetExceeded` (or anything else) and the cascade records the failure and
continues with the next strategy, because in practice one broken path is normal.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from .mathutil import BudgetExceeded

FlagPattern = str
DEFAULT_FLAG_PATTERN = r"(?:[A-Za-z][A-Za-z0-9_]{0,15}\{[^}\r\n]{2,200}\})"

# How much to trust a match from a given solver when several produce one.
# Brute-force catch-alls that wrap any text score lower than a keyed decrypt.
SOLVER_TRUST: dict[str, float] = {
    "affine_bruteforce": 0.35,
    "caesar_bruteforce": 0.35,
    "railfence_bruteforce": 0.45,
    "encoding_peel": 0.7,
    "flag_pattern_scan": 0.5,
}
DEFAULT_TRUST = 1.0


@dataclass
class Candidate:
    data: bytes
    source: str
    note: str = ""
    wrapped: bool = False

    def text(self) -> str:
        return self.data.decode("utf-8", "replace")


@dataclass
class SolveContext:
    report: dict
    deadline: float
    flag_pattern: str = DEFAULT_FLAG_PATTERN
    source_text: str = ""
    output_text: str = ""
    output_bytes: bytes = b""
    log: list[str] = field(default_factory=list)

    # ---- convenience accessors -------------------------------------------
    @property
    def params(self) -> dict:
        return self.report.get("params", {}) or {}

    def emit(self, data: bytes, source: str, note: str = "") -> Candidate:
        cand = Candidate(data, source, note)
        self.log.append(f"  -> {source}: {len(data)}B {_preview(data)}")
        return cand

    def flag_in(self, data: bytes) -> str | None:
        """Case-insensitive match; returns the flag exactly as produced."""
        m = re.search(self.flag_pattern.encode(), data, re.IGNORECASE)
        return m.group(0).decode("utf-8", "replace") if m else None

    def flag_prefix(self) -> str | None:
        """Literal prefix the flag pattern expects, if one can be named safely.

        Handles three shapes: an explicit prefix (`FLAG{...}`), an alternation
        (`(?:GETSFLAG|FLAG){...}` -> first alternative) and the generic default
        pattern, which implies the conventional `FLAG` prefix.
        """
        pat = self.flag_pattern.strip()
        m = re.match(r"([A-Za-z0-9_]{2,16})\\?\{", pat)
        if m:
            return m.group(1)
        alt = re.match(r"\(\?:([A-Za-z0-9_|]{2,64})\)", pat)
        if alt:
            first = alt.group(1).split("|")[0].strip()
            if re.fullmatch(r"[A-Za-z0-9_]{2,16}", first or ""):
                return first
        if pat.startswith("(?:"):
            return "FLAG"
        return None

    def wrap(self, plain: str, source: str) -> list["Candidate"]:
        """Candidates for alpha-only output whose braces were stripped.

        Reinserts the pattern's prefix and drops the usual trailing pad, so
        `flagabcx` also yields `FLAG{abc}`.
        """
        out: list[Candidate] = [Candidate(plain.encode("utf-8", "replace"), source)]
        prefix = self.flag_prefix()
        if not prefix:
            return out
        low = plain.lower().strip()
        if low.startswith(prefix.lower()):
            low = low[len(prefix):]
        low = low.lstrip("_").rstrip("x")
        if re.fullmatch(r"[a-z0-9_]{3,120}", low or ""):
            out.append(Candidate(f"{prefix}{{{low}}}".encode(), f"{source} [braces restored]", wrapped=True))
        return out

    def wrap_inline(self, plain: str, source: str) -> "Candidate | None":
        """Return only the restored flag form, for solvers that never emit braces."""
        prefix = self.flag_prefix()
        if not prefix:
            return None
        low = plain.lower().strip()
        if not low.startswith(prefix.lower()):
            return None
        low = low[len(prefix):].lstrip("_").rstrip("x")
        if not re.fullmatch(r"[a-z0-9_]{3,120}", low or ""):
            return None
        return Candidate(f"{prefix}{{{low}}}".encode(), f"{source} [braces restored]", wrapped=True)


@dataclass
class CascadeResult:
    flag: str | None
    matched_source: str | None
    attempts: list[dict]
    candidates: list[Candidate]
    stopped_reason: str

    def ok(self) -> bool:
        return self.flag is not None

    def as_dict(self) -> dict:
        return {
            "flag": self.flag,
            "matched_source": self.matched_source,
            "attempts": self.attempts,
            "candidate_count": len(self.candidates),
            "stopped_reason": self.stopped_reason,
        }


def _preview(data: bytes, limit: int = 48) -> str:
    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:limit])
    return printable + ("..." if len(data) > limit else "")


def _load_output(ctx: SolveContext) -> bytes:
    path = ctx.report.get("output_path")
    if not path:
        return b""
    try:
        return Path(path).read_bytes()
    except OSError:
        return b""


def build_context(report: dict, flag_pattern: str | None = None, total_seconds: float = 90.0) -> SolveContext:
    src_path = report.get("script_path")
    src = ""
    if src_path:
        try:
            src = Path(src_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            src = ""
    ctx = SolveContext(
        report=report,
        deadline=time.monotonic() + max(5.0, total_seconds),
        flag_pattern=flag_pattern or DEFAULT_FLAG_PATTERN,
        source_text=src,
        output_text=report.get("_output_text", "") or "",
    )
    ctx.output_bytes = _load_output(ctx)
    if not ctx.output_text and ctx.output_bytes:
        ctx.output_text = ctx.output_bytes.decode("latin-1")
    return ctx


def run_cascade(
    report: dict,
    flag_pattern: str | None = None,
    total_seconds: float = 90.0,
    solvers: dict[str, Callable[[SolveContext], Iterable[Candidate]]] | None = None,
) -> CascadeResult:
    from .solvers import REGISTRY

    table = solvers or REGISTRY
    ctx = build_context(report, flag_pattern, total_seconds)
    plan: list[str] = list(report.get("plan") or [])
    attempts: list[dict] = []
    found: list[Candidate] = []
    flag: str | None = None
    matched: str | None = None
    matched_solver: str | None = None
    reason = "plan exhausted"

    for name in plan:
        solver = table.get(name)
        if solver is None:
            attempts.append({"solver": name, "status": "unregistered", "seconds": 0.0, "candidates": 0})
            continue
        if time.monotonic() > ctx.deadline:
            reason = f"deadline reached before {name}"
            attempts.append({"solver": name, "status": "skipped", "seconds": 0.0, "candidates": 0})
            break
        t0 = time.monotonic()
        try:
            raw_produced = list(solver(ctx) or [])
            status = "ok" if raw_produced else "empty"
        except BudgetExceeded as exc:
            raw_produced, status = [], f"budget: {exc}"
        except Exception as exc:  # a solver failing is data, not a stop condition
            raw_produced, status = [], f"{type(exc).__name__}: {exc}"
        dt = time.monotonic() - t0
        trust = SOLVER_TRUST.get(name, DEFAULT_TRUST)
        produced: list[Candidate] = []
        for cand in raw_produced:
            if ctx.flag_in(cand.data):
                cand.note = f"{cand.note} trust={trust}".strip()
                produced.append(cand)
                continue
            # A braces-stripped classical result still counts once wrapped.
            if ctx.flag_prefix() and len(cand.data) >= 6 and b"{" not in cand.data:
                for wrapped in ctx.wrap(cand.text(), cand.source)[1:]:
                    if ctx.flag_in(wrapped.data):
                        wrapped.note = f"trust={trust}"
                        produced.append(wrapped)
                        break
        found.extend(produced)
        attempts.append({
            "solver": name,
            "status": status,
            "seconds": round(dt, 3),
            "candidates": len(produced),
            "trust": trust,
        })

        # Highest-trust match wins; keep scanning while only weak solvers fired.
        best = None
        for cand in produced:
            hit = ctx.flag_in(cand.data)
            if not hit:
                continue
            if best is None or trust > best[0]:
                best = (trust, hit, cand.source)
        if best and (flag is None or best[0] > SOLVER_TRUST.get(matched_solver or "", DEFAULT_TRUST)):
            flag, matched, matched_solver = best[1], best[2], name
            reason = f"flag from {name} (trust {best[0]})"
        if flag and SOLVER_TRUST.get(matched_solver or "", DEFAULT_TRUST) >= DEFAULT_TRUST:
            break

    if flag is None and found:
        reason = "candidates produced, no flag pattern matched"
    return CascadeResult(flag, matched, attempts, found, reason)
