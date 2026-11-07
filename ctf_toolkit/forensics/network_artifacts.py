from __future__ import annotations

import math
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path

try:
    import dpkt
except ImportError:
    dpkt = None


@dataclass(slots=True)
class NetworkArtifactResult:
    output_dir: Path
    backend: str
    packets: int
    exported_http_objects: int
    exported_smb_objects: int
    user_agents: list[str]
    destination_ips: list[str]
    dns_queries: list[str]
    suspicious_dns_queries: list[str]


def _reader_for(path: Path):
    handle = path.open("rb")
    magic = handle.read(4)
    handle.seek(0)
    if magic == b"\x0a\x0d\x0d\x0a":
        return handle, dpkt.pcapng.Reader(handle)
    return handle, dpkt.pcap.Reader(handle)


def _safe_filename(name: str, fallback: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]", "_", (name or "").strip())
    if not clean:
        clean = fallback
    return clean[:120]


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    size = len(text)
    entropy = 0.0
    for count in counts.values():
        prob = count / size
        entropy -= prob * math.log2(prob)
    return entropy


def _is_suspicious_dns(query: str) -> bool:
    value = query.strip().lower()
    if not value:
        return False
    parts = [part for part in value.split(".") if part]
    longest = max((len(part) for part in parts), default=0)
    digit_ratio = sum(ch.isdigit() for ch in value) / max(1, len(value))
    entropy = _shannon_entropy(value)
    return len(value) > 70 or longest > 40 or digit_ratio > 0.30 or entropy > 4.2


def _maybe_tshark_export(pcap_path: Path, output_dir: Path) -> bool:
    if shutil.which("tshark") is None:
        return False

    http_dir = output_dir / "http_objects"
    smb_dir = output_dir / "smb_objects"
    http_dir.mkdir(parents=True, exist_ok=True)
    smb_dir.mkdir(parents=True, exist_ok=True)

    commands = [
        ["tshark", "-r", str(pcap_path), "--export-objects", f"http,{http_dir}"],
        ["tshark", "-r", str(pcap_path), "--export-objects", f"smb,{smb_dir}"],
    ]
    for command in commands:
        subprocess.run(command, check=False, capture_output=True, text=True)
    return True


def extract_network_artifacts(
    pcap_path: str,
    output_root: str = "output",
    prefer_tshark: bool = True,
    max_http_object_size: int = 5 * 1024 * 1024,
    max_exported_smb_objects: int = 500,
    max_tracked_items: int = 20000,
) -> NetworkArtifactResult:
    source = Path(pcap_path)
    if not source.exists() or not source.is_file():
        raise FileNotFoundError(f"file pcap tidak ditemukan: {source}")

    output_dir = Path(output_root) / f"network_{source.stem}"
    output_dir.mkdir(parents=True, exist_ok=True)
    exported_dir = output_dir / "exported_objects"
    exported_dir.mkdir(parents=True, exist_ok=True)

    backend = "dpkt"
    if prefer_tshark and _maybe_tshark_export(source, output_dir):
        backend = "tshark+dpkt"

    user_agents: set[str] = set()
    destination_ips: set[str] = set()
    dns_queries: set[str] = set()
    suspicious_dns: set[str] = set()

    packets = 0
    http_count = 0
    smb_count = 0

    handle, reader = _reader_for(source)
    try:
        for _, packet in reader:
            packets += 1
            try:
                eth = dpkt.ethernet.Ethernet(packet)
            except (dpkt.NeedData, dpkt.UnpackError):
                continue

            ip = getattr(eth, "data", None)
            if isinstance(ip, dpkt.ip.IP):
                if len(destination_ips) < max_tracked_items:
                    destination_ips.add(socket.inet_ntoa(ip.dst))
            elif isinstance(ip, dpkt.ip6.IP6):
                if len(destination_ips) < max_tracked_items:
                    destination_ips.add(socket.inet_ntop(socket.AF_INET6, ip.dst))
            else:
                continue

            transport = getattr(ip, "data", None)
            payload = b""
            if isinstance(transport, dpkt.tcp.TCP):
                payload = bytes(transport.data or b"")
            elif isinstance(transport, dpkt.udp.UDP):
                payload = bytes(transport.data or b"")

            if not payload:
                continue

            if isinstance(transport, dpkt.tcp.TCP) and payload.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ")):
                try:
                    request = dpkt.http.Request(payload)
                except (dpkt.NeedData, dpkt.UnpackError):
                    request = None
                if request:
                    user_agent = request.headers.get("user-agent", "")
                    if user_agent:
                        if len(user_agents) < max_tracked_items:
                            user_agents.add(user_agent[:200])

            if isinstance(transport, dpkt.tcp.TCP) and payload.startswith(b"HTTP/"):
                try:
                    response = dpkt.http.Response(payload)
                except (dpkt.NeedData, dpkt.UnpackError):
                    response = None
                if response and response.body and len(response.body) <= max_http_object_size:
                    disposition = response.headers.get("content-disposition", "")
                    file_match = re.search(r'filename="?([^";]+)"?', disposition, flags=re.IGNORECASE)
                    filename = file_match.group(1) if file_match else f"http_obj_{packets}.bin"
                    object_path = exported_dir / _safe_filename(filename, f"http_obj_{packets}.bin")
                    if not object_path.exists():
                        object_path.write_bytes(response.body)
                        http_count += 1

            if (
                isinstance(transport, dpkt.tcp.TCP)
                and smb_count < max_exported_smb_objects
                and (b"\xffSMB" in payload or b"\xfeSMB" in payload)
            ):
                chunk = payload[: min(len(payload), 32768)]
                object_path = exported_dir / f"smb_chunk_{packets}.bin"
                object_path.write_bytes(chunk)
                smb_count += 1

            is_dns = False
            if isinstance(transport, dpkt.udp.UDP) and (transport.sport == 53 or transport.dport == 53):
                is_dns = True
            if isinstance(transport, dpkt.tcp.TCP) and (transport.sport == 53 or transport.dport == 53):
                is_dns = True

            if is_dns:
                try:
                    dns = dpkt.dns.DNS(payload)
                except (dpkt.NeedData, dpkt.UnpackError):
                    continue
                for question in dns.qd or []:
                    name = getattr(question, "name", "").strip().lower()
                    if not name:
                        continue
                    if len(dns_queries) < max_tracked_items:
                        dns_queries.add(name)
                    if _is_suspicious_dns(name) and len(suspicious_dns) < max_tracked_items:
                        suspicious_dns.add(name)
    finally:
        handle.close()

    user_agents_sorted = sorted(user_agents)
    destination_ips_sorted = sorted(destination_ips)
    dns_sorted = sorted(dns_queries)
    suspicious_sorted = sorted(suspicious_dns)

    (output_dir / "user_agents.txt").write_text("\n".join(user_agents_sorted) or "(none)\n", encoding="utf-8")
    (output_dir / "destination_ips.txt").write_text("\n".join(destination_ips_sorted) or "(none)\n", encoding="utf-8")
    (output_dir / "dns_queries.txt").write_text("\n".join(dns_sorted) or "(none)\n", encoding="utf-8")
    (output_dir / "dns_suspicious.txt").write_text("\n".join(suspicious_sorted) or "(none)\n", encoding="utf-8")

    summary = [
        f"backend: {backend}",
        f"pcap: {source}",
        f"packets parsed: {packets}",
        f"http objects exported: {http_count}",
        f"smb objects exported: {smb_count}",
        f"unique user-agents: {len(user_agents_sorted)}",
        f"unique destination ips: {len(destination_ips_sorted)}",
        f"dns queries: {len(dns_sorted)}",
        f"suspicious dns queries: {len(suspicious_sorted)}",
    ]
    (output_dir / "summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")

    return NetworkArtifactResult(
        output_dir=output_dir,
        backend=backend,
        packets=packets,
        exported_http_objects=http_count,
        exported_smb_objects=smb_count,
        user_agents=user_agents_sorted,
        destination_ips=destination_ips_sorted,
        dns_queries=dns_sorted,
        suspicious_dns_queries=suspicious_sorted,
    )


def render_network_report(result: NetworkArtifactResult) -> str:
    lines = [
        "Network Artifact Report",
        f"Backend                 : {result.backend}",
        f"Packets Parsed          : {result.packets}",
        f"HTTP Objects Exported   : {result.exported_http_objects}",
        f"SMB Objects Exported    : {result.exported_smb_objects}",
        f"Unique User-Agents      : {len(result.user_agents)}",
        f"Unique Destination IPs  : {len(result.destination_ips)}",
        f"DNS Queries             : {len(result.dns_queries)}",
        f"Suspicious DNS Queries  : {len(result.suspicious_dns_queries)}",
        "",
        "Top User-Agents:",
    ]
    lines.extend(f"- {value}" for value in result.user_agents[:20])
    lines.append("")
    lines.append("Top Destination IPs:")
    lines.extend(f"- {value}" for value in result.destination_ips[:20])
    lines.append("")
    lines.append("Suspicious DNS Queries:")
    lines.extend(f"- {value}" for value in result.suspicious_dns_queries[:50])
    return "\n".join(lines) + "\n"


def extract_dns_hex_subdomains(pcap_data: bytes, domain_suffix: str = "evil-dns.id") -> bytes:
    """Extract concatenated hex-encoded subdomain labels from DNS queries in PCAP."""
    import re

    pattern = rf"([0-9a-fA-F]+)\.t\.{re.escape(domain_suffix)}"
    matches = re.findall(pattern.encode("latin-1"), pcap_data)
    hex_str = b"".join(matches).decode("latin-1")
    return bytes.fromhex(hex_str)


def assemble_icmp_echo_payloads(pcap_data: bytes) -> bytes:
    """Extract sequential ICMP Echo Request payloads from raw PCAP bytes."""
    import struct

    endian = "<" if pcap_data[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    offset = 24
    frags: list[bytes] = []

    while offset + 16 <= len(pcap_data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", pcap_data[offset : offset + 16])
        offset += 16
        pkt = pcap_data[offset : offset + incl_len]
        offset += incl_len

        if len(pkt) > 34 and pkt[12:14] == b"\x08\x00" and pkt[23] == 1:
            ip_hdr_len = (pkt[14] & 0x0F) * 4
            trans_off = 14 + ip_hdr_len
            payload = pkt[trans_off + 8 :]
            if payload.startswith(b"\x08"):
                frags.append(payload[1:])

    return b"".join(frags)


def extract_dns_base32_subdomains(pcap_data: bytes, domain_suffix: str = "exfil-c2.net") -> bytes:
    """Extract Base32 subdomain query fragments and decode to bytes."""
    import base64
    import re

    pattern = rf"([a-z2-7A-Z2-7]{{10,}})\.dns\.{re.escape(domain_suffix)}"
    matches = re.findall(pattern.encode("latin-1"), pcap_data)
    b32_str = b"".join(matches).decode("latin-1").upper()
    pad = (8 - len(b32_str) % 8) % 8
    return base64.b32decode(b32_str + "=" * pad)


def decode_dns_xor_b32_beacon(
    pcap_data: bytes, domain_suffix: str = "telemetry-hub.io", xor_key: bytes = b"GF"
) -> bytes:
    """Extract indexed Base32 DNS queries, decode, and un-XOR with repeating key."""
    import base64
    import re

    pattern = rf"(\d\d)([a-z2-70-9A-Z2-70-9]{{20,}})\.ns1\.{re.escape(domain_suffix)}"
    queries = re.findall(pattern.encode("latin-1"), pcap_data)
    queries.sort(key=lambda x: x[0])
    b32_str = b"".join(q[1] for q in queries).decode("latin-1").upper()
    pad = (8 - len(b32_str) % 8) % 8
    dec = base64.b32decode(b32_str + "=" * pad)
    return bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(dec))


def reassemble_tcp_stream_seq(pcap_data: bytes, filter_port: int | None = None) -> bytes:
    """Reassemble TCP payload segments ordered by TCP Sequence Number."""
    import struct

    endian = "<" if pcap_data[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    offset = 24
    segments: list[tuple[int, bytes]] = []

    while offset + 16 <= len(pcap_data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", pcap_data[offset : offset + 16])
        offset += 16
        pkt = pcap_data[offset : offset + incl_len]
        offset += incl_len

        if len(pkt) > 34 and pkt[12:14] == b"\x08\x00" and pkt[23] == 6:
            ip_hdr_len = (pkt[14] & 0x0F) * 4
            trans_off = 14 + ip_hdr_len
            src_port, dst_port, seq = struct.unpack(">HHI", pkt[trans_off : trans_off + 8])
            if filter_port is None or src_port == filter_port or dst_port == filter_port:
                tcp_hdr_len = ((pkt[trans_off + 12] >> 4) & 0x0F) * 4
                payload = pkt[trans_off + tcp_hdr_len :]
                if payload:
                    segments.append((seq, payload))

    segments.sort(key=lambda x: x[0])
    return b"".join(s[1] for s in segments)
