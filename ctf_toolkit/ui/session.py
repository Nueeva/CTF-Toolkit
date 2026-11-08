from __future__ import annotations

import base64
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class SessionState:
    active_case: str = "default_case"
    registers: dict[str, Any] = field(default_factory=dict)
    history: list[dict[str, Any]] = field(default_factory=list)
    captured_flags: list[dict[str, str]] = field(default_factory=list)
    case_notes: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)


_GLOBAL_SESSION = SessionState()


def get_session() -> SessionState:
    """Return the global workbench session instance."""
    return _GLOBAL_SESSION


def reset_session(case_name: str = "default_case") -> SessionState:
    """Reset session state for a new CTF challenge case."""
    global _GLOBAL_SESSION
    _GLOBAL_SESSION = SessionState(active_case=case_name)
    return _GLOBAL_SESSION


def set_last_output(data: Any, op_name: str = "operation") -> None:
    """Store output in $last and numbered registers $1, $2, etc."""
    session = get_session()
    session.registers["$last"] = data
    reg_idx = f"${len(session.history) + 1}"
    session.registers[reg_idx] = data

    entry = {
        "index": len(session.history) + 1,
        "op": op_name,
        "data": data,
        "timestamp": time.time(),
        "type": type(data).__name__,
        "size": len(data) if isinstance(data, (bytes, str, list, dict)) else 0,
    }
    session.history.append(entry)

    # Automatically scan for flags
    scan_and_record_flags(data, source=op_name)


def get_register(name: str, default: Any = None) -> Any:
    """Retrieve register value by name (e.g. '$last', '$1', '$2')."""
    session = get_session()
    clean_name = name.strip()
    if not clean_name.startswith("$"):
        clean_name = "$" + clean_name
    return session.registers.get(clean_name, default)


def scan_and_record_flags(data: Any, source: str = "") -> list[str]:
    """Scan data for standard CTF flag patterns and save them to the Flag Vault."""
    if not data:
        return []
    text = ""
    if isinstance(data, bytes):
        text = data.decode("latin1", errors="ignore")
    elif isinstance(data, str):
        text = data
    elif isinstance(data, (list, tuple, dict)):
        text = str(data)

    patterns = [
        r"(?:FLAG|CTF|GETSFLAG|LKS|LKSJAKTIM|picoCTF|HTB|SECCON)\{[^\n\r\}]{1,300}\}",
        r"[A-Za-z0-9_-]{3,20}\{[^\n\r\}]{4,300}\}",
    ]
    found = []
    session = get_session()
    existing_flags = {item["flag"] for item in session.captured_flags}

    for pat in patterns:
        matches = re.findall(pat, text, re.IGNORECASE)
        for m in matches:
            if m not in existing_flags and m not in found:
                found.append(m)
                session.captured_flags.append({
                    "flag": m,
                    "source": source or "inspector",
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                })
                existing_flags.add(m)
    return found


def resolve_smart_input(raw: str, as_bytes: bool = False) -> Any:
    """Resolve smart inputs:
    - '$last' or '$1' -> session register value
    - '@path/to/file' -> content of file
    - 'hex:414243' -> bytes.fromhex('414243')
    - 'b64:QUJD' -> base64 decoded bytes
    - standard text -> string (or bytes if as_bytes=True)
    """
    cleaned = raw.strip()
    if not cleaned:
        return b"" if as_bytes else ""

    # 1. Register lookup ($last, $1, $2, ...)
    if cleaned.startswith("$"):
        val = get_register(cleaned)
        if val is not None:
            if as_bytes and isinstance(val, str):
                return val.encode("utf-8", errors="ignore")
            if not as_bytes and isinstance(val, bytes):
                try:
                    return val.decode("utf-8")
                except UnicodeDecodeError:
                    return val.decode("latin1", errors="replace")
            return val
        # If not found in registers, fall through

    # 2. File reference (@path/to/file)
    if cleaned.startswith("@"):
        fpath = Path(cleaned[1:].strip().strip('"').strip("'"))
        if fpath.exists():
            if as_bytes:
                return fpath.read_bytes()
            try:
                return fpath.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                return fpath.read_text(encoding="latin1", errors="replace")
        else:
            raise FileNotFoundError(f"File tidak ditemukan: {fpath}")

    # 3. Explicit hex encoding (hex:4142...)
    if cleaned.lower().startswith("hex:"):
        hex_data = cleaned[4:].strip()
        data = bytes.fromhex(hex_data)
        return data if as_bytes else data.decode("latin1", errors="replace")

    # 4. Explicit base64 encoding (b64:...)
    if cleaned.lower().startswith("b64:"):
        b64_data = cleaned[4:].strip()
        data = base64.b64decode(b64_data)
        return data if as_bytes else data.decode("latin1", errors="replace")

    # 5. Default pass-through
    if as_bytes:
        return cleaned.encode("utf-8")
    return cleaned


def copy_to_clipboard(data: Any) -> bool:
    """Copy string representation of data to OS clipboard."""
    text = ""
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.hex()
    else:
        text = str(data)

    # 1. Try pyperclip if installed
    try:
        import pyperclip
        pyperclip.copy(text)
        return True
    except Exception:
        pass

    # 2. Windows clip.exe
    if os.name == "nt":
        try:
            p = subprocess.Popen(["clip"], stdin=subprocess.PIPE, shell=True)
            p.communicate(text.encode("utf-16le"))
            return True
        except Exception:
            pass

    # 3. Linux/macOS pbcopy / xclip
    for cmd in [["pbcopy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]:
        try:
            p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
            p.communicate(text.encode("utf-8"))
            return True
        except Exception:
            continue

    return False


def export_case_script(filepath: str | None = None) -> str:
    """Export the current session history into a standalone Python solver script."""
    session = get_session()
    case_name = re.sub(r"[^a-zA-Z0-9_]", "_", session.active_case)
    if not filepath:
        filepath = f"solve_{case_name}.py"

    lines = [
        "#!/usr/bin/env python3",
        '"""',
        f"CTF Automated Solver Script - Case: {session.active_case}",
        f"Generated by CTF-Toolkit v3 Apex Workbench on {time.strftime('%Y-%m-%d %H:%M:%S')}",
        '"""',
        "from __future__ import annotations",
        "import base64",
        "import re",
        "import sys",
        "from ctf_toolkit.pipeline import run_recipe",
        "",
        "def solve():",
        f"    print('[*] Running solver for {session.active_case}...')",
    ]

    if not session.history:
        lines.append("    # No operations recorded in session history.")
        lines.append("    pass")
    else:
        for idx, step in enumerate(session.history, 1):
            op = step.get("op", "operation")
            lines.append(f"    # Step {idx}: {op}")
            if op.startswith("recipe:"):
                recipe_str = op[7:]
                lines.append(f"    data_{idx} = run_recipe({recipe_str!r}, data_{idx-1} if {idx} > 1 else b'')")
            else:
                lines.append(f"    # op: {op}")

    if session.captured_flags:
        lines.append("")
        for f in session.captured_flags:
            lines.append(f"    # Captured Flag: {f['flag']} (from {f['source']})")
        lines.append(f"    print('[+] Flag captured: {session.captured_flags[0]['flag']}')")
    lines.extend([
        "",
        "if __name__ == '__main__':",
        "    solve()",
    ])

    code = "\n".join(lines) + "\n"
    Path(filepath).write_text(code, encoding="utf-8")
    return filepath


def export_case_writeup(filepath: str | None = None) -> str:
    """Export the current session history into a professional CTF Writeup markdown document."""
    session = get_session()
    case_name = re.sub(r"[^a-zA-Z0-9_]", "_", session.active_case)
    if not filepath:
        filepath = f"WRITEUP_{case_name}.md"

    lines = [
        f"# CTF Writeup: {session.active_case}",
        f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}  ",
        "**Toolkit:** CTF-Toolkit v3 Apex Command Center  ",
        "",
        "## 1. Executive Summary",
        f"- **Target Challenge:** `{session.active_case}`",
        f"- **Total Operations Executed:** {len(session.history)}",
        f"- **Flags Captured:** {len(session.captured_flags)}",
        "",
    ]

    if session.captured_flags:
        lines.append("### Captured Flags")
        for f in session.captured_flags:
            lines.append(f"- **`{f['flag']}`** *(source: {f['source']} at {f['time']})*")
        lines.append("")

    lines.append("## 2. Step-by-Step Investigation & Solution Pipeline")
    if not session.history:
        lines.append("*No interactive steps were recorded in this session.*")
    else:
        lines.append("| Step | Operation | Data Type | Output Size | Timestamp |")
        lines.append("| :---: | :--- | :---: | :---: | :--- |")
        for step in session.history:
            lines.append(
                f"| {step['index']} | `{step['op']}` | `{step['type']}` | {step['size']} bytes | {time.strftime('%H:%M:%S', time.localtime(step['timestamp']))} |"
            )
        lines.append("")

    lines.extend([
        "## 3. Automation Script",
        f"Refer to companion script `solve_{case_name}.py` generated automatically by CTF-Toolkit.",
        "",
        "---",
        "*Document generated by CTF-Toolkit v3.*",
    ])

    doc = "\n".join(lines) + "\n"
    Path(filepath).write_text(doc, encoding="utf-8")
    return filepath


def add_captured_flag(flag: str, source: str = "") -> None:
    """Add a flag directly to the session Flag Vault."""
    session = get_session()
    existing = {item["flag"] for item in session.captured_flags}
    if flag not in existing:
        session.captured_flags.append({
            "flag": flag,
            "source": source or "manual",
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
