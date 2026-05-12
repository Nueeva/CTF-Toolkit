from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def _select_decompiler() -> list[str]:
    if shutil.which("pycdc"):
        return ["pycdc"]
    if shutil.which("uncompyle6"):
        return ["uncompyle6", "--stdout"]
    raise FileNotFoundError("pycdc atau uncompyle6 tidak ditemukan")


def decompile_pyc(path: str) -> tuple[str, str]:
    file_path = Path(path)
    if file_path.suffix.lower() != ".pyc":
        raise ValueError("file harus berekstensi .pyc")
    if not file_path.exists():
        raise ValueError("file tidak ditemukan")
    cmd = _select_decompiler()
    proc = subprocess.run(
        [*cmd, str(file_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        err = (proc.stderr or "").strip() or "decompiler gagal"
        raise ValueError(err)
    return cmd[0], proc.stdout


def decompile_pyc_if_applicable(path: str) -> tuple[str, str] | None:
    file_path = Path(path)
    if file_path.suffix.lower() != ".pyc":
        return None
    return decompile_pyc(path)
