from __future__ import annotations

from pathlib import Path
import re

import dpkt

from ctf_toolkit.utils.text import extract_printable_strings

PCAP_KEYWORDS = ("flag", "ctf", "key", "lks", "lksjaktim")
FLAG_PATTERNS = [
    re.compile(r"LKS\{[^\n\r}]{1,200}\}", flags=re.IGNORECASE),
    re.compile(r"LKSJAKTIM\{[^\n\r}]{1,200}\}", flags=re.IGNORECASE),
    re.compile(r"LKS[-_\s]?JAKTIM\{[^\n\r}]{1,200}\}", flags=re.IGNORECASE),
    re.compile(r"[A-Za-z0-9_\-]+\{[^\n\r}]{1,200}\}", flags=re.IGNORECASE),
]


def _reader_for(path: Path):
    handle = path.open("rb")
    magic = handle.read(4)
    handle.seek(0)
    if magic == b"\x0a\x0d\x0d\x0a":
        return handle, dpkt.pcapng.Reader(handle)
    return handle, dpkt.pcap.Reader(handle)


def _ascii(text: bytes, limit: int = 1200) -> str:
    return text[:limit].decode("utf-8", errors="ignore")


def _collect_hits(lines: list[str]) -> list[str]:
    hits: list[str] = []
    seen: set[str] = set()
    for line in lines:
        low = line.lower()
        if any(keyword in low for keyword in PCAP_KEYWORDS):
            if line not in seen:
                hits.append(line)
                seen.add(line)
        for pattern in FLAG_PATTERNS:
            for match in pattern.findall(line):
                if match not in seen:
                    hits.append(match)
                    seen.add(match)
    return hits


def extract_pcap_artifacts(path: str, output_root: str = "output") -> Path:
    pcap_path = Path(path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"file tidak ditemukan: {pcap_path}")

    out_dir = Path(output_root) / f"pcap_{pcap_path.stem}"
    out_dir.mkdir(parents=True, exist_ok=True)

    http_lines: list[str] = []
    tcp_strings: list[str] = []
    dns_lines: list[str] = []
    raw_strings: list[str] = []

    packet_count = 0
    handle, reader = _reader_for(pcap_path)
    try:
        for _, pkt in reader:
            packet_count += 1
            try:
                eth = dpkt.ethernet.Ethernet(pkt)
            except (dpkt.NeedData, dpkt.UnpackError):
                continue

            ip = getattr(eth, "data", None)
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue

            transport = getattr(ip, "data", None)

            raw_payload = b""
            if isinstance(transport, dpkt.tcp.TCP):
                raw_payload = bytes(transport.data or b"")
                if raw_payload:
                    if raw_payload.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"HTTP/")):
                        http_lines.append(f"[pkt {packet_count}] {_ascii(raw_payload)}")
                    tcp_strings.extend(extract_printable_strings(raw_payload, min_len=4))
            elif isinstance(transport, dpkt.udp.UDP):
                raw_payload = bytes(transport.data or b"")

            if raw_payload:
                raw_strings.extend(extract_printable_strings(raw_payload, min_len=4))

            is_dns = False
            if isinstance(transport, dpkt.udp.UDP) and (transport.sport == 53 or transport.dport == 53):
                is_dns = True
            if isinstance(transport, dpkt.tcp.TCP) and (transport.sport == 53 or transport.dport == 53):
                is_dns = True

            if is_dns and raw_payload:
                try:
                    dns = dpkt.dns.DNS(raw_payload)
                except (dpkt.NeedData, dpkt.UnpackError):
                    continue
                if dns.qd:
                    for question in dns.qd:
                        dns_lines.append(f"[pkt {packet_count}] DNS Q: {question.name}")
                if dns.an:
                    for answer in dns.an:
                        if answer.type == dpkt.dns.DNS_TXT:
                            txt = getattr(answer, "text", [])
                            txt_value = " ".join(
                                t.decode("utf-8", errors="ignore") if isinstance(t, bytes) else str(t)
                                for t in txt
                            )
                            dns_lines.append(f"[pkt {packet_count}] DNS TXT: {answer.name} -> {txt_value}")
                        elif answer.type in (dpkt.dns.DNS_A, dpkt.dns.DNS_AAAA, dpkt.dns.DNS_CNAME):
                            dns_lines.append(f"[pkt {packet_count}] DNS ANS: {answer.name}")
    finally:
        handle.close()

    unique_tcp = sorted(set(tcp_strings))
    unique_raw = sorted(set(raw_strings))
    all_text = http_lines + dns_lines + unique_tcp + unique_raw
    hits = _collect_hits(all_text)

    (out_dir / "http.txt").write_text("\n".join(http_lines) or "(no http payload found)\n", encoding="utf-8")
    (out_dir / "tcp_strings.txt").write_text(
        "\n".join(unique_tcp) or "(no printable tcp strings found)\n", encoding="utf-8"
    )
    (out_dir / "dns.txt").write_text("\n".join(dns_lines) or "(no dns entries found)\n", encoding="utf-8")
    (out_dir / "raw_strings.txt").write_text(
        "\n".join(unique_raw[:10000]) or "(no raw printable strings found)\n", encoding="utf-8"
    )
    (out_dir / "hits.txt").write_text("\n".join(hits) or "(no keyword/flag hits found)\n", encoding="utf-8")
    summary = "\n".join(
        [
            f"pcap: {pcap_path}",
            f"packets parsed: {packet_count}",
            f"http entries: {len(http_lines)}",
            f"tcp strings: {len(unique_tcp)}",
            f"dns entries: {len(dns_lines)}",
            f"raw strings: {len(unique_raw)}",
            f"keyword/flag hits: {len(hits)}",
        ]
    )
    (out_dir / "summary.txt").write_text(summary + "\n", encoding="utf-8")

    return out_dir
