#!/usr/bin/env python3
"""Build a single-file portable Python zipapp (dist/ctf-toolkit.pyz) for CTF-Toolkit.

This bundle can be copied onto restricted CTF jumpboxes, air-gapped competition VMs,
or Linux/Windows/macOS hosts and executed directly via:
    python ctf-toolkit.pyz
"""
from __future__ import annotations

import shutil
import tempfile
import zipapp
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

    with tempfile.TemporaryDirectory() as tmp_dir:
        staging = Path(tmp_dir) / "bundle"
        staging.mkdir(parents=True, exist_ok=True)

        # Copy ctf_toolkit package excluding __pycache__
        src_pkg = ROOT_DIR / "ctf_toolkit"
        dst_pkg = staging / "ctf_toolkit"
        shutil.copytree(
            src_pkg,
            dst_pkg,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
        )

        zipapp.create_archive(
            staging,
            target=output_path,
            interpreter="/usr/bin/env python3",
            main="ctf_toolkit.main_cli:main",
            compressed=True,
        )

    return output_path


if __name__ == "__main__":
    out = build_pyz()
    print(f"[+] Portable single-file bundle created: {out} ({out.stat().st_size} bytes)")
    print(f"    Run with: python {out}")
