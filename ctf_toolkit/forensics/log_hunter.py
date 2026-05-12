from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from pathlib import Path

ACCESS_LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<url>[^\s"]+)(?:\s+HTTP/[0-9.]+)?"\s+(?P<status>\d{3})(?:\s+\S+){0,2}$'
)
SYSLOG_RE = re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(?P<body>.*)$")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PATH_TRAVERSAL_RE = re.compile(r"(\.\./|%2e%2e%2f|%252e%252e%252f|/etc/passwd)", flags=re.IGNORECASE)
SQLI_RE = re.compile(
    r"('\s*or\s*'1'='1|\bor\s+1=1\b|union\s+select|information_schema|sleep\s*\(|benchmark\s*\(|--|/\*)",
    flags=re.IGNORECASE,
)


@dataclass(slots=True)
class Incident:
    time: str
    source_ip: str
    attack_type: str
    target: str


def _valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def _extract_syslog_parts(line: str) -> tuple[str, str, str]:
    match = SYSLOG_RE.match(line)
    if not match:
        return "-", "-", line.strip()[:160]
    event_time = match.group("time")
    body = match.group("body")
    ip_match = IP_RE.search(body)
    source_ip = ip_match.group(0) if ip_match else "-"
    return event_time, source_ip, body.strip()[:160]


def _parse_file_sync(path: Path, brute_threshold: int) -> list[Incident]:
    incidents: list[Incident] = []
    brute_counter: dict[str, int] = {}
    brute_alerted: set[str] = set()

    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue

            access_match = ACCESS_LOG_RE.match(line)
            if access_match:
                source_ip = access_match.group("ip")
                if not _valid_ipv4(source_ip):
                    continue
                event_time = access_match.group("time")
                url = access_match.group("url")
                status = int(access_match.group("status"))

                if PATH_TRAVERSAL_RE.search(url):
                    incidents.append(Incident(event_time, source_ip, "Path Traversal", url[:180]))
                if SQLI_RE.search(url):
                    incidents.append(Incident(event_time, source_ip, "SQL Injection", url[:180]))

                if status in (401, 403):
                    brute_counter[source_ip] = brute_counter.get(source_ip, 0) + 1
                    if brute_counter[source_ip] >= brute_threshold and source_ip not in brute_alerted:
                        incidents.append(
                            Incident(
                                event_time,
                                source_ip,
                                "Bruteforce Suspected",
                                f"status={status}, attempts={brute_counter[source_ip]}",
                            )
                        )
                        brute_alerted.add(source_ip)
                continue

            lowered = line.lower()
            if "failed password" in lowered or "authentication failure" in lowered:
                event_time, source_ip, target = _extract_syslog_parts(line)
                incidents.append(Incident(event_time, source_ip, "Auth Failure", target))

            if PATH_TRAVERSAL_RE.search(line):
                event_time, source_ip, target = _extract_syslog_parts(line)
                incidents.append(Incident(event_time, source_ip, "Path Traversal", target))

            if SQLI_RE.search(line):
                event_time, source_ip, target = _extract_syslog_parts(line)
                incidents.append(Incident(event_time, source_ip, "SQL Injection", target))

    unique: list[Incident] = []
    seen: set[tuple[str, str, str, str]] = set()
    for incident in incidents:
        key = (incident.time, incident.source_ip, incident.attack_type, incident.target)
        if key in seen:
            continue
        seen.add(key)
        unique.append(incident)
    return unique


async def hunt_log_patterns(paths: list[str], brute_threshold: int = 5) -> list[Incident]:
    existing_paths: list[Path] = []
    for path in paths:
        path_obj = Path(path)
        if path_obj.exists() and path_obj.is_file():
            existing_paths.append(path_obj)

    if not existing_paths:
        raise FileNotFoundError("tidak ada file log valid yang ditemukan")

    tasks = [asyncio.to_thread(_parse_file_sync, path_obj, brute_threshold) for path_obj in existing_paths]
    grouped = await asyncio.gather(*tasks)
    incidents = [incident for group in grouped for incident in group]
    incidents.sort(key=lambda item: (item.time, item.source_ip, item.attack_type))
    return incidents


def incident_rows(incidents: list[Incident]) -> list[list[str]]:
    rows: list[list[str]] = []
    for incident in incidents:
        rows.append([incident.time, incident.source_ip, incident.attack_type, incident.target])
    return rows


def render_incident_report(incidents: list[Incident]) -> str:
    headers = ["Time", "Source IP", "Attack Type", "Target URL"]
    rows = incident_rows(incidents)
    if not rows:
        return "Incident Report\n(no incident detected)\n"

    widths = [len(header) for header in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))

    lines = ["Incident Report", " | ".join(header.ljust(widths[idx]) for idx, header in enumerate(headers))]
    lines.append("-" * len(lines[1]))
    for row in rows:
        lines.append(" | ".join(cell.ljust(widths[idx]) for idx, cell in enumerate(row)))
    lines.append(f"Total incidents: {len(rows)}")
    return "\n".join(lines) + "\n"
