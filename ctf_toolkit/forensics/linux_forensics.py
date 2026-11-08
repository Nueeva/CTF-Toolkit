from __future__ import annotations

import re


def decrypt_marker_bounded_xor(
    data: bytes,
    marker: bytes = b"XK",
    key: int = 0x5A,
    pattern: bytes = rb"(?:TECHCOMFEST\d*|COMPFEST\d*|GEMASTIK\d*|WRECKIT\d*|HOLOGY\d*|SLASHROOT\d*|GETSFLAG|CTFLEARN|picoCTF|SEKAI|HIDC\d*|ARA\d*|CHTB|HTB|THM|ASIS|DICE|HOPE|OOO|ARKAV|LACTF|ACTF|LKS|CTF|FLAG|CT)\{[^}]+\}",
) -> list[str]:
    """
    Locate segments enclosed by markers (or entire payload if marker absent),
    XOR decrypt with key, and extract discovered flags.
    """
    segments: list[bytes] = []
    if marker and marker in data:
        parts = data.split(marker)
        if len(parts) >= 3:
            for i in range(1, len(parts), 2):
                segments.append(parts[i])
        else:
            segments.append(data)
    else:
        segments.append(data)

    results: list[str] = []
    for seg in segments:
        decrypted = bytes(b ^ key for b in seg)
        matches = re.findall(pattern, decrypted, re.IGNORECASE)
        for m in matches:
            decoded = m.decode("utf-8", errors="ignore")
            if decoded not in results:
                results.append(decoded)
    return results


def audit_etc_passwd(passwd_text: str) -> list[dict[str, str]]:
    """Identify rogue accounts in `/etc/passwd` (UID 0 non-root accounts, unexpected login shells, or hidden notes)."""
    findings: list[dict[str, str]] = []
    for line in passwd_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        user, pw, uid, gid, gecos, home, shell = parts[:7]
        is_suspicious = (
            (uid == "0" and user != "root")
            or ("FLAG{" in line or "GETSFLAG{" in line or "CT{" in line)
            or (pw not in ("x", "*", "!") and len(pw) > 1)
            or (shell.endswith(("sh", "bash", "zsh")) and user not in ("root", "ubuntu", "admin", "debian"))
        )
        if is_suspicious:
            findings.append({
                "user": user,
                "uid": uid,
                "gid": gid,
                "gecos": gecos,
                "home": home,
                "shell": shell,
                "raw": line,
            })
    return findings


def audit_sshd_config(config_text: str) -> list[str]:
    """Identify insecure directives or embedded flags in `sshd_config`."""
    anomalies: list[str] = []
    for line in config_text.splitlines():
        clean = line.strip()
        if not clean:
            continue
        if any(k in clean.lower() for k in ("permitrootlogin yes", "permitemptypasswords yes", "passwordauthentication yes", "flag{", "getsflag{")):
            anomalies.append(clean)
    return anomalies


def audit_authorized_keys(keys_text: str) -> list[str]:
    """Extract SSH public key comments, command= options, and anomalous entries from `.ssh/authorized_keys`."""
    entries: list[str] = []
    for line in keys_text.splitlines():
        clean = line.strip()
        if not clean or clean.startswith("#"):
            continue
        entries.append(clean)
    return entries
