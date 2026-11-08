"""APK and DEX extraction helpers for CTF reversing and forensics."""
from __future__ import annotations

import io
import re
import struct
import zipfile
from pathlib import Path
from typing import Any


def extract_dex_strings(data: bytes | str | Path) -> list[str]:
    """
    Extract string constants directly from a DEX file (.dex) or APK archive.
    Parses string_ids table when standard DEX header is present, with fallback to printable scan.
    """
    if isinstance(data, (str, Path)):
        raw = Path(data).read_bytes()
    else:
        raw = bytes(data)

    # If it's an APK / ZIP archive, extract all .dex files inside
    if raw.startswith(b"PK\x03\x04"):
        all_strings: list[str] = []
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                for name in zf.namelist():
                    if name.endswith(".dex"):
                        dex_data = zf.read(name)
                        all_strings.extend(extract_dex_strings(dex_data))
            return list(dict.fromkeys(all_strings))
        except Exception:
            pass

    strings: list[str] = []
    # DEX magic: b"dex\n035\x00" through "dex\n039\x00"
    if raw.startswith(b"dex\n") and len(raw) >= 0x70:
        try:
            string_ids_size = struct.unpack_from("<I", raw, 56)[0]
            string_ids_off = struct.unpack_from("<I", raw, 60)[0]
            if 0 < string_ids_size < 1_000_000 and 0 < string_ids_off < len(raw):
                for i in range(string_ids_size):
                    off_pos = string_ids_off + i * 4
                    if off_pos + 4 > len(raw):
                        break
                    str_data_off = struct.unpack_from("<I", raw, off_pos)[0]
                    if str_data_off >= len(raw):
                        continue
                    # Read ULEB128 utf16_size
                    pos = str_data_off
                    utf16_size = 0
                    shift = 0
                    while pos < len(raw):
                        b = raw[pos]
                        pos += 1
                        utf16_size |= (b & 0x7F) << shift
                        if (b & 0x80) == 0:
                            break
                        shift += 7
                    # Read null-terminated MUTF-8 string
                    null_pos = raw.find(b"\x00", pos)
                    if null_pos != -1:
                        s_bytes = raw[pos:null_pos]
                        try:
                            s = s_bytes.decode("utf-8", errors="ignore")
                            if s:
                                strings.append(s)
                        except Exception:
                            pass
        except Exception:
            pass

    # Regex fallback for strings >= 4 chars
    if not strings:
        matches = re.findall(rb"[A-Za-z0-9+/=_\-.{}!?:@#$%\^&*()]{4,}", raw)
        for m in matches:
            s = m.decode("latin-1", errors="ignore")
            if s not in strings:
                strings.append(s)

    return list(dict.fromkeys(strings))


def extract_apk_manifest_strings(apk_data: bytes | str | Path) -> list[str]:
    """Extract readable strings from binary AndroidManifest.xml inside an APK."""
    if isinstance(apk_data, (str, Path)):
        raw = Path(apk_data).read_bytes()
    else:
        raw = bytes(apk_data)

    manifest_bytes = b""
    if raw.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    manifest_bytes = zf.read("AndroidManifest.xml")
        except Exception:
            pass
    elif b"manifest" in raw.lower() or raw.startswith(b"\x03\x00\x08\x00"):
        manifest_bytes = raw

    if not manifest_bytes:
        return []

    # Binary XML String Pool parsing
    strings: list[str] = []
    # UTF-16 and ASCII search
    utf16_matches = re.findall(rb"(?:[\x20-\x7e]\x00){3,}", manifest_bytes)
    for m in utf16_matches:
        s = m.decode("utf-16le", errors="ignore")
        if s and s not in strings:
            strings.append(s)

    ascii_matches = re.findall(rb"[a-zA-Z0-9_.\-/:]{4,}", manifest_bytes)
    for m in ascii_matches:
        s = m.decode("latin-1", errors="ignore")
        if s and s not in strings:
            strings.append(s)

    return strings


def inspect_apk_components(apk_data: bytes | str | Path) -> dict[str, Any]:
    """Inspect APK archive contents: dex files, resources, native libraries, and manifest indicators."""
    if isinstance(apk_data, (str, Path)):
        raw = Path(apk_data).read_bytes()
    else:
        raw = bytes(apk_data)

    result: dict[str, Any] = {
        "files": [],
        "dex_files": [],
        "native_libs": [],
        "has_manifest": False,
        "flags_found": [],
    }

    if not raw.startswith(b"PK\x03\x04"):
        return result

    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            for name in zf.namelist():
                result["files"].append(name)
                if name.endswith(".dex"):
                    result["dex_files"].append(name)
                elif name.startswith("lib/") and name.endswith(".so"):
                    result["native_libs"].append(name)
                elif name == "AndroidManifest.xml":
                    result["has_manifest"] = True

            # Scan files for flags
            for name in zf.namelist()[:50]:
                content = zf.read(name)
                flags = re.findall(rb"(?:TECHCOMFEST\d*|COMPFEST\d*|GEMASTIK\d*|WRECKIT\d*|HOLOGY\d*|SLASHROOT\d*|GETSFLAG|CTFLEARN|picoCTF|SEKAI|HIDC\d*|ARA\d*|CHTB|HTB|THM|ASIS|DICE|HOPE|OOO|ARKAV|LACTF|ACTF|LKS|CTF|FLAG|CT)\{[^}\s]{3,100}\}", content, re.IGNORECASE)
                for f in flags:
                    flag_str = f.decode("latin-1", errors="ignore")
                    if flag_str not in result["flags_found"]:
                        result["flags_found"].append(flag_str)
    except Exception:
        pass

    return result
