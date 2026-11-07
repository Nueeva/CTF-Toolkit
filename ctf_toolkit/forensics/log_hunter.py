from __future__ import annotations

import asyncio
import base64
import re
from dataclasses import dataclass
from pathlib import Path
import urllib.parse

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
    for item in parts:
        if not item.isdigit() or not 0 <= int(item) <= 255:
            return False
    return True


def parse_access_log_line(line: str) -> dict[str, str] | None:
    match = ACCESS_LOG_RE.match(line.strip())
    if not match:
        return None
    data = match.groupdict()
    if not _valid_ipv4(data["ip"]):
        return None
    return data


def detect_line_incident(line: str) -> Incident | None:
    parsed = parse_access_log_line(line)
    if not parsed:
        return None

    url = parsed["url"]
    if PATH_TRAVERSAL_RE.search(url):
        return Incident(
            time=parsed["time"],
            source_ip=parsed["ip"],
            attack_type="Path Traversal",
            target=url,
        )
    if SQLI_RE.search(url):
        return Incident(
            time=parsed["time"],
            source_ip=parsed["ip"],
            attack_type="SQL Injection",
            target=url,
        )
    return None


async def hunt_file(path: Path) -> list[Incident]:
    if not path.is_file():
        return []

    incidents: list[Incident] = []
    loop = asyncio.get_running_loop()
    lines = await loop.run_in_executor(None, path.read_text, "utf-8", "ignore")
    for raw_line in lines.splitlines():
        item = detect_line_incident(raw_line)
        if item:
            incidents.append(item)
    return incidents


async def hunt_directory(root: str | Path, recursive: bool = True) -> list[Incident]:
    target = Path(root)
    if not target.exists():
        return []

    iterator = target.rglob("*") if recursive else target.glob("*")
    files = [item for item in iterator if item.is_file() and item.suffix in {".log", ".txt", ""}]
    if not files:
        return []

    tasks = [hunt_file(file) for file in files]
    results = await asyncio.gather(*tasks)
    merged: list[Incident] = []
    for batch in results:
        merged.extend(batch)
    return merged


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


def extract_dns_subdomain_exfiltration(log_text: str, target_domain: str) -> bytes:
    """
    Extracts ordered DNS query subdomain chunks for a specific apex domain,
    strips sequence numbering prefixes (e.g. q00-, q01-), and decodes hex.
    """
    pattern = rf"query\[[A-Za-z]+\]\s+([^\s]*{re.escape(target_domain)})"
    queries = re.findall(pattern, log_text)
    unique_sorted = sorted(set(queries))
    hex_chunks = []
    for q in unique_sorted:
        label = q.split(".")[0]
        if "-" in label:
            hex_chunks.append(label.split("-", 1)[1])
        else:
            hex_chunks.append(label)

    full_hex = "".join(hex_chunks)
    try:
        return bytes.fromhex(full_hex)
    except Exception:
        return full_hex.encode()


def assemble_suricata_alert_fragments(log_text: str) -> bytes:
    """
    Extracts segmented base64 covert fragments from Suricata ET EXFIL alerts,
    orders them by frag=X/Y index, concatenates and decodes.
    """
    pattern = r"frag=(\d+)/(\d+)\s+data=([^\s\]]+)"
    matches = re.findall(pattern, log_text)
    if not matches:
        return b""
    frags: dict[int, str] = {}
    for idx_str, total_str, data_str in matches:
        frags[int(idx_str)] = data_str

    ordered_b64 = "".join(frags[i] for i in sorted(frags.keys()))
    try:
        return base64.b64decode(ordered_b64)
    except Exception:
        return ordered_b64.encode()


def extract_b64_url_parameters(log_text: str, param_names: list[str] | None = None) -> list[bytes]:
    """
    Scans access log query strings for base64 encoded parameter values.
    """
    if param_names is None:
        param_names = ["data", "v", "payload", "msg", "q", "token", "sync"]

    names_pat = "|".join(re.escape(p) for p in param_names)
    pattern = rf"(?:{names_pat})=([A-Za-z0-9%+/=]+)"
    results: list[bytes] = []
    for cand in re.findall(pattern, log_text):
        cand_unquoted = urllib.parse.unquote(cand)
        try:
            dec = base64.b64decode(cand_unquoted)
            if dec:
                results.append(dec)
        except Exception:
            pass
    return results


def extract_usb_serial_hex(log_text: str) -> list[bytes]:
    """
    Finds USB SerialNumber hex-encoded descriptors in kernel dmesg / kern.log.
    """
    pattern = r"SerialNumber:\s+([0-9a-fA-F]{16,})"
    results: list[bytes] = []
    for match in re.findall(pattern, log_text):
        try:
            dec = bytes.fromhex(match)
            results.append(dec)
        except Exception:
            pass
    return results


def extract_mime_encoded_words(log_text: str) -> list[str]:
    """
    Decodes MIME encoded-word syntax (=?charset?B?payload?=) in email subjects.
    """
    pattern = r"=\?[^?]+\?[Bb]\?([^?]+)\?="
    results: list[str] = []
    for cand in re.findall(pattern, log_text):
        try:
            dec = base64.b64decode(cand).decode("utf-8", errors="ignore")
            results.append(dec)
        except Exception:
            pass
    return results


def assemble_dns_b32_exfiltration(log_text: str, domain_suffix: str = "beacon.c2-shadowfox.ru") -> bytes:
    """
    Assemble ordered Base32 DNS queries with prefix s<index>.<base32>.<domain_suffix> and decode to bytes.
    """
    pattern = rf"s(\d+)\.([A-Za-z0-9=]+)\.{re.escape(domain_suffix)}"
    frags: dict[int, str] = {}
    for m in re.finditer(pattern, log_text, re.IGNORECASE):
        idx = int(m.group(1))
        frags[idx] = m.group(2)
    b32_str = "".join(frags[i] for i in sorted(frags.keys())).upper()
    pad = (8 - len(b32_str) % 8) % 8
    return base64.b32decode(b32_str + "=" * pad)


def correlate_multi_log_fragments(log_sources: list[str]) -> str:
    """
    Correlate log records carrying XFRAG=<index>:<b64_data> across multiple files and decode Base64 payload.
    """
    frags: dict[int, str] = {}
    for text in log_sources:
        for m in re.finditer(r"XFRAG=(\d+):([A-Za-z0-9+/=]+)", text):
            frags[int(m.group(1))] = m.group(2)
    b64_str = "".join(frags[i] for i in sorted(frags.keys()))
    pad = (4 - len(b64_str) % 4) % 4
    return base64.b64decode(b64_str + "=" * pad).decode("utf-8", errors="ignore")


def extract_edr_beacon_sequence(log_text: str) -> str:
    """
    Extract sequenced numeric telemetry values (seq=<idx> size=<ord>) and convert to ASCII characters.
    """
    telem: dict[int, int] = {}
    for m in re.finditer(r"seq=(\d+)\s+size=(\d+)", log_text):
        telem[int(m.group(1))] = int(m.group(2))
    return "".join(chr(telem[i]) for i in sorted(telem.keys()))

