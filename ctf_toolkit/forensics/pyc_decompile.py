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

    # 1. Regex search for printable ASCII strings length >= 4 including braces and punctuation
    ascii_matches = re.findall(rb"[A-Za-z0-9+/=_ \-{}!?:@#$%\^&*()]{4,}", raw_bytes)
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



def solve_pyc_byte_transform(
    pyc_bytes: bytes,
    mode: str = "auto",
    key: int = 0,
    key2: int = 0,
) -> list[str]:
    """
    Extract byte/integer sequences from Python `.pyc` marshal streams and invert common
    byte transformations (`add`, `sub`, `xor`, `index_sub`, `index_add`, `parity_2const`).
    """
    import re

    candidates: list[str] = list(extract_pyc_constants_raw(pyc_bytes))
    # Extract small integer sequences packed with marshal TYPE_INT ('i' = 0x69 + 4-byte LE int)
    int_seqs: list[list[int]] = []
    cur_seq: list[int] = []
    i = 0
    while i < len(pyc_bytes) - 5:
        if pyc_bytes[i] == 0x69:
            val = int.from_bytes(pyc_bytes[i + 1 : i + 5], "little", signed=True)
            if 0 <= val <= 255:
                cur_seq.append(val)
                i += 5
                continue
        if len(cur_seq) >= 6:
            int_seqs.append(cur_seq)
        cur_seq = []
        i += 1
    if len(cur_seq) >= 6:
        int_seqs.append(cur_seq)

    for seq in int_seqs:
        raw = bytes(seq)
        # Try direct, add, sub, xor, index transforms
        transforms: list[bytes] = [
            raw,
            bytes((b + i) & 0xFF for i, b in enumerate(raw)),
            bytes((b - i) & 0xFF for i, b in enumerate(raw)),
            bytes(b ^ (i & 0xFF) for i, b in enumerate(raw)),
        ]
        if key:
            transforms.extend([
                bytes((b + key) & 0xFF for b in raw),
                bytes((b - key) & 0xFF for b in raw),
                bytes(b ^ (key & 0xFF) for b in raw),
            ])
            if key2:
                transforms.append(
                    bytes(b ^ ((key2 if (idx & 1) else key) & 0xFF) for idx, b in enumerate(raw))
                )
        else:
            for k in range(1, 256):
                transforms.append(bytes((b - k) & 0xFF for b in raw))
                transforms.append(bytes(b ^ k for b in raw))

        for t in transforms:
            text = t.decode("latin-1", errors="ignore")
            if re.search(r"(?:TECHCOMFEST\d*|COMPFEST\d*|GEMASTIK\d*|WRECKIT\d*|HOLOGY\d*|SLASHROOT\d*|GETSFLAG|CTFLEARN|picoCTF|SEKAI|HIDC\d*|ARA\d*|CHTB|HTB|THM|ASIS|DICE|HOPE|OOO|ARKAV|LACTF|ACTF|LKS|CTF|FLAG|CT)\{[ -~]+\}", text, re.IGNORECASE):
                if text not in candidates:
                    candidates.insert(0, text)
    return candidates
