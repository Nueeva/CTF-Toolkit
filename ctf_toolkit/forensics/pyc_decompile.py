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

def extract_pyc_constants_raw(data_or_path: bytes | str | Path) -> list[str]:
    """
    Extract embedded string constants and decode candidate Base32/Base64/ASCII tokens
    from compiled Python bytecode (.pyc) directly from raw bytes, independent of Python runtime version.
    """
    import base64
    import re

    raw_bytes: bytes
    if isinstance(data_or_path, (str, Path)):
        with open(data_or_path, "rb") as f:
            raw_bytes = f.read()
    else:
        raw_bytes = data_or_path

    extracted: list[str] = []

    # 1. Regex search for printable ASCII strings length >= 6
    ascii_matches = re.findall(rb"[A-Za-z0-9+/=_ -]{6,}", raw_bytes)
    for m in ascii_matches:
        s = m.decode("latin1", errors="ignore").strip()
        if s and s not in extracted:
            extracted.append(s)

        # Candidate Base32 check
        clean_b32 = s.rstrip("=")
        if len(clean_b32) >= 8 and re.match(r"^[A-Z2-7]+$", clean_b32):
            padded = clean_b32 + "=" * ((8 - len(clean_b32) % 8) % 8)
            try:
                dec = base64.b32decode(padded).decode("utf-8", errors="ignore")
                if dec.isprintable() and len(dec) >= 3 and dec not in extracted:
                    extracted.append(dec)
            except Exception:
                pass

        # Candidate Base64 check
        clean_b64 = s.rstrip("=")
        if len(clean_b64) >= 8 and re.match(r"^[A-Za-z0-9+/]+$", clean_b64):
            padded_b64 = clean_b64 + "=" * ((4 - len(clean_b64) % 4) % 4)
            try:
                dec_b64 = base64.b64decode(padded_b64).decode("utf-8", errors="ignore")
                if dec_b64.isprintable() and len(dec_b64) >= 3 and dec_b64 not in extracted:
                    extracted.append(dec_b64)
            except Exception:
                pass

    return extracted

