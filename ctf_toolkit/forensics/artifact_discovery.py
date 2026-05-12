from __future__ import annotations

import platform
import shlex
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class ArtifactPath:
    category: str
    path: str
    note: str


def windows_artifact_paths(user_profile: str = "%USERPROFILE%") -> list[ArtifactPath]:
    profile = user_profile.rstrip("\\/")
    return [
        ArtifactPath("Browser History", f"{profile}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", "Chrome history DB"),
        ArtifactPath("Browser History", f"{profile}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History", "Edge history DB"),
        ArtifactPath("Browser History", f"{profile}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles", "Firefox profile folder"),
        ArtifactPath("Prefetch", r"C:\\Windows\\Prefetch", "Executed program traces"),
        ArtifactPath(
            "Shimcache",
            r"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
            "Registry location (query with reg.exe)",
        ),
        ArtifactPath("AppData", f"{profile}\\AppData\\Local", "User local app data"),
        ArtifactPath("AppData", f"{profile}\\AppData\\Roaming", "User roaming app data"),
    ]


def linux_artifact_paths(home_dir: str = "~") -> list[ArtifactPath]:
    home = home_dir.rstrip("/")
    return [
        ArtifactPath("Shell History", f"{home}/.bash_history", "Bash command history"),
        ArtifactPath("Cron", "/etc/crontab", "System cron schedule"),
        ArtifactPath("Cron", "/etc/cron.d", "Additional cron jobs"),
        ArtifactPath("Cron", f"{home}/.config/crontab", "User cron configuration (if present)"),
        ArtifactPath("Account", "/etc/passwd", "Account list, check modification time"),
        ArtifactPath("Account", "/etc/shadow", "Credential hashes (root access needed)"),
        ArtifactPath("SSH", f"{home}/.ssh/authorized_keys", "Authorized SSH keys"),
    ]


def quick_discovery(target_os: str = "auto") -> tuple[str, list[ArtifactPath]]:
    lowered = target_os.strip().lower()
    if lowered not in {"auto", "windows", "linux"}:
        raise ValueError("target_os harus auto/windows/linux")

    if lowered == "auto":
        detected = platform.system().lower()
        lowered = "windows" if "win" in detected else "linux"

    if lowered == "windows":
        return "windows", windows_artifact_paths()
    return "linux", linux_artifact_paths()


def artifact_rows(items: list[ArtifactPath]) -> list[list[str]]:
    return [[item.category, item.path, item.note] for item in items]


def generate_hash_oneliner(items: list[ArtifactPath], target_os: str) -> str:
    lowered = target_os.lower().strip()
    paths = [item.path for item in items]

    if lowered == "windows":
        escaped = [value.replace("'", "''") for value in paths]
        list_expr = ",".join(f"'{value}'" for value in escaped)
        return (
            "powershell -NoProfile -Command \""
            f"$files=@({list_expr});"
            "foreach($f in $files){"
            "if(Test-Path $f){"
            "Get-FileHash -Algorithm MD5 $f;"
            "Get-FileHash -Algorithm SHA256 $f"
            "}}\""
        )

    quoted = " ".join(shlex.quote(path) for path in paths)
    return (
        "for f in "
        f"{quoted}; "
        "do [ -e \"$f\" ] && md5sum \"$f\" && sha256sum \"$f\"; "
        "done"
    )


def render_discovery_report(target_os: str, items: list[ArtifactPath]) -> str:
    lines = [f"Digital Artifact Discovery ({target_os})", "Category | Path | Note", "-" * 80]
    for item in items:
        lines.append(f"{item.category} | {item.path} | {item.note}")
    lines.append("")
    lines.append("Hash One-Liner:")
    lines.append(generate_hash_oneliner(items, target_os))
    lines.append("")
    return "\n".join(lines)
