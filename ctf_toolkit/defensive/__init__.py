"""Defensive / Blue Team security auditing, log forensics, and artifact discovery primitives."""

from __future__ import annotations

from typing import Any

from ctf_toolkit.forensics.artifact_discovery import generate_hash_oneliner, quick_discovery
from ctf_toolkit.forensics.linux_forensics import audit_etc_passwd, audit_sshd_config
from ctf_toolkit.forensics.log_hunter import parse_access_log_line
from ctf_toolkit.forensics.malware_helper import check_file_header, extract_interesting_strings


def audit_system_hardening(passwd_text: str, sshd_config_text: str = "") -> dict[str, Any]:
    """Run defensive hardening audit across `/etc/passwd` and `sshd_config` contents."""
    return {
        "passwd_findings": audit_etc_passwd(passwd_text),
        "sshd_findings": audit_sshd_config(sshd_config_text) if sshd_config_text else [],
    }


def correlate_incident_logs(access_log_text: str, status_filter: int = 0) -> list[dict[str, Any]]:
    """Parse and correlate HTTP access log lines for incident response triage."""
    events: list[dict[str, Any]] = []
    for line in access_log_text.splitlines():
        if not line.strip():
            continue
        parsed = parse_access_log_line(line)
        if parsed is None:
            continue
        if status_filter and int(parsed.get("status", 0)) != status_filter:
            continue
        events.append(parsed)
    return events


def inspect_suspicious_header(filepath: str) -> dict[str, Any]:
    """Check a file's magic byte header against its extension for defensive malware triage."""
    return check_file_header(filepath)


def discover_host_artifacts(target_os: str = "auto") -> dict[str, Any]:
    """Discover forensic artifact paths and hash verification commands for the target OS."""
    detected_os, artifacts = quick_discovery(target_os=target_os)
    return {
        "os": detected_os,
        "artifact_count": len(artifacts),
        "hash_oneliner": generate_hash_oneliner(artifacts, detected_os),
    }


__all__ = [
    "audit_etc_passwd",
    "audit_sshd_config",
    "audit_system_hardening",
    "check_file_header",
    "correlate_incident_logs",
    "discover_host_artifacts",
    "extract_interesting_strings",
    "generate_hash_oneliner",
    "inspect_suspicious_header",
    "parse_access_log_line",
    "quick_discovery",
]
