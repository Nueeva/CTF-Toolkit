from __future__ import annotations

import re
from pathlib import Path

REQUEST_PATTERN = re.compile(r"\brequest\.(get_json\(\)|form)\b")
UNPACK_PATTERN = re.compile(r"\*\*\s*request\.(get_json\(\)|form)\b")
DB_CONTEXT_PATTERN = re.compile(
    r"(db\.session\.add|db\.session\.bulk|db\.session\.execute|"
    r"\.create\(|\.update\(|\.save\(|insert\(|update\(|\bModel\b)",
    flags=re.IGNORECASE,
)


def _iter_target_files(root: Path, names: list[str]) -> list[Path]:
    found: dict[str, Path] = {}
    for name in names:
        for path in root.rglob(name):
            found[str(path)] = path
    return sorted(found.values(), key=lambda p: str(p))


def scan_mass_assignment_text(text: str) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        if not REQUEST_PATTERN.search(line):
            continue
        reason = ""
        if UNPACK_PATTERN.search(line):
            reason = "unpacked request payload"
        elif DB_CONTEXT_PATTERN.search(line):
            reason = "request payload used in db operation"
        if not reason:
            continue
        results.append(
            {
                "line": idx,
                "snippet": line.strip(),
                "reason": reason,
            }
        )
    return results


def scan_mass_assignment_files(root: str, filenames: list[str] | None = None) -> list[dict[str, object]]:
    root_path = Path(root)
    if not root_path.exists():
        raise ValueError("root path tidak ditemukan")
    names = filenames or ["app.py", "models.py"]
    results: list[dict[str, object]] = []
    for path in _iter_target_files(root_path, names):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        matches = scan_mass_assignment_text(text)
        for match in matches:
            results.append(
                {
                    "file": str(path),
                    **match,
                }
            )
    return results
