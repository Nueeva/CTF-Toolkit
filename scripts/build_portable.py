#!/usr/bin/env python3
"""Build a TRULY portable single-file bundle (dist/ctf-toolkit.pyz).

Uses shiv: the toolkit AND all of its pip dependencies (including native
wheels such as pycryptodome, numpy and opencv) are packed into one .pyz.
On first run the bundle extracts its site-packages into a per-user cache
(~/.shiv), so native extensions load correctly — a plain zipapp cannot
do that, which is why the previous bundle crashed on machines without
the dependencies preinstalled.

Requirements (build machine only):  pip install shiv
Target machine: only Python 3.10+ — no pip installs needed.

    python scripts/build_portable.py
    python dist/ctf-toolkit.pyz --version
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
DIST_DIR = ROOT_DIR / "dist"


def build_pyz(output_path: Path | None = None) -> Path:
    if output_path is None:
        DIST_DIR.mkdir(parents=True, exist_ok=True)
        output_path = DIST_DIR / "ctf-toolkit.pyz"
    else:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        import shiv  # noqa: F401
    except ImportError:
        raise SystemExit(
            "shiv is required to build the portable bundle: pip install shiv"
        )

    if output_path.exists():
        output_path.unlink()

    # -c ctf-toolkit: console-script entry point from pyproject.toml.
    # Shiv pip-installs the project + every dependency into the archive.
    subprocess.run(
        [
            sys.executable, "-m", "shiv",
            "-c", "ctf-toolkit",
            "-o", str(output_path),
            str(ROOT_DIR),
        ],
        check=True,
    )
    return output_path


if __name__ == "__main__":
    out = build_pyz()
    print(f"[+] Portable single-file bundle created: {out} ({out.stat().st_size} bytes)")
    print(f"    Run with: python {out}")
    print("    First run extracts bundled dependencies into ~/.shiv (one-time).")
