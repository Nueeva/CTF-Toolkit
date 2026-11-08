from __future__ import annotations

from pathlib import Path
import re
import struct

try:
    import dpkt
except ImportError:
    dpkt = None

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


def _unpack_packet_ip(pkt: bytes, datalink: int | None = None):
    """
    Unpack IP/IPv6 layer from link-layer packet, handling Ethernet, LINKTYPE_NULL,
    LINKTYPE_LINUX_SLL, and Raw IP frames.
    """
    if dpkt is None:
        return None

    # Handle explicit datalink types
    if datalink == 0:  # LINKTYPE_NULL / BSD loopback (4 bytes AF family)
        try:
            return dpkt.loopback.Loopback(pkt).data
        except Exception:
            try:
                return dpkt.ip.IP(pkt[4:])
            except Exception:
                pass
    elif datalink == 113:  # LINKTYPE_LINUX_SLL (cooked packet, 16 bytes header)
        try:
            return dpkt.sll.SLL(pkt).data
        except Exception:
            pass
    elif datalink in (12, 101):  # Raw IPv4 / IPv6
        try:
            return dpkt.ip.IP(pkt)
        except Exception:
            try:
                return dpkt.ip6.IP6(pkt)
            except Exception:
                pass

    # Standard Ethernet parser
    try:
        eth = dpkt.ethernet.Ethernet(pkt)
        ip = getattr(eth, "data", None)
        if isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return ip
    except Exception:
        pass

    # Generic fallbacks
    try:
        sll = dpkt.sll.SLL(pkt)
        if isinstance(sll.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return sll.data
    except Exception:
        pass

    try:
        loop = dpkt.loopback.Loopback(pkt)
        if isinstance(loop.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return loop.data
    except Exception:
        pass

    if len(pkt) > 4:
        try:
            return dpkt.ip.IP(pkt[4:])
        except Exception:
            pass

    try:
        return dpkt.ip.IP(pkt)
    except Exception:
        try:
            return dpkt.ip6.IP6(pkt)
        except Exception:
            return None


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
    datalink = getattr(reader, "datalink", None)
    try:
        for _, pkt in reader:
            packet_count += 1
            ip = _unpack_packet_ip(pkt, datalink)
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


def extract_http_basic_auth(pcap_source: bytes | str | Path) -> list[str]:
    """
    Extract HTTP Basic Authorization header credentials (base64 decoded) from raw PCAP or file path.
    """
    import base64

    if isinstance(pcap_source, (str, Path)):
        with open(pcap_source, "rb") as f:
            data = f.read()
    else:
        data = bytes(pcap_source)

    results: list[str] = []
    for m in re.finditer(rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", data, re.IGNORECASE):
        try:
            dec = base64.b64decode(m.group(1)).decode("utf-8", errors="ignore")
            if dec and dec not in results:
                results.append(dec)
        except Exception:
            pass
    return results


def repair_pcap_header(data: bytes, linktype: int = 1) -> bytes:
    """
    Repair or prepend a valid 24-byte libpcap file header for damaged PCAP captures.
    Recognizes swapped endianness, missing headers, or corrupted magic bytes.
    """
    if len(data) >= 4:
        magic = data[:4]
        if magic in (
            b"\xa1\xb2\xc3\xd4",
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\x3c\x4d",
            b"\x4d\x3c\xb2\xa1",
            b"\x0a\x0d\x0d\x0a",
        ):
            if len(data) >= 24:
                return data

    canonical_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)

    if len(data) > 24 and data[4:8] in (b"\x00\x02\x00\x04", b"\x02\x00\x04\x00"):
        return canonical_hdr + data[24:]

    return canonical_hdr + data


def decrypt_pcap_tls_keylog(pcap_source: str | Path | bytes, keylog_source: str | Path | bytes) -> dict[str, object]:
    """
    Parse NSS keylog file (SSLKEYLOGFILE) and return extracted session keys and metadata
    for TLS decryption.
    """
    if isinstance(keylog_source, Path):
        keylog_text = keylog_source.read_text("utf-8", errors="ignore")
    elif isinstance(keylog_source, bytes):
        keylog_text = keylog_source.decode("utf-8", errors="ignore")
    else:
        keylog_text = str(keylog_source)

    keys: dict[str, str] = {}
    for line in keylog_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 3 and parts[0] in (
            "CLIENT_RANDOM",
            "RSA",
            "EXPORTER_SECRET",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_TRAFFIC_SECRET_0",
            "CLIENT_TRAFFIC_SECRET_0",
        ):
            keys[parts[1]] = parts[2]

    return {
        "status": "keys_parsed",
        "keys_count": len(keys),
        "keys": keys,
        "note": "Session keys extracted. Can be supplied to tshark (-o tls.keylog_file) or Wireshark.",
    }
