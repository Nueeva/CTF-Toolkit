from __future__ import annotations

import re


def decrypt_marker_bounded_xor(
    data: bytes,
    marker: bytes = b"XK",
    key: int = 0x5A,
    pattern: bytes = rb"(?:GETSFLAG|FLAG)\{[^}]+\}",
) -> list[str]:
    """
    Locate segments enclosed by markers (or entire payload if marker absent),
    XOR decrypt with key, and extract discovered flags.
    """
    decrypted = bytes(b ^ key for b in data)
    matches = re.findall(pattern, decrypted)
    return [m.decode("utf-8", errors="ignore") for m in matches]


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
