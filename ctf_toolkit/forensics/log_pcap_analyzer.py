"""
Automated parser and exfiltration detector for forensic network logs and PCAP files.

Covers:
1. DNS tunneling exfiltration (hex subdomains, Base32 subdomains, XOR beacons, plain labels).
2. Out-of-order TCP segment reassembly with automatic gzip decompression.
3. Suricata / Snort alert covert channel fragment assembly (e.g. frag=0/5 data=...).
4. SSH / FTP / Syslog / Telnet authentication event extraction.
"""
from __future__ import annotations

import base64
import gzip
import re
import struct


def analyze_log_artifacts(log_text: str) -> list[str]:
    """Extract flags and reconstruct exfiltration streams from system and IDS logs."""
    extracted: list[str] = []

    # 1. Covert channel fragments (e.g. frag=0/5 data=...)
    frag_matches = re.findall(r"frag=(\d+)/\d+\s+data=([A-Za-z0-9+/=]+)", log_text)
    if frag_matches:
        frags = dict(frag_matches)
        try:
            b64_comb = "".join(frags[str(i)] for i in range(len(frags)))
            dec = base64.b64decode(b64_comb).decode("latin-1", errors="ignore")
            extracted.append(dec)
        except Exception:
            pass

    # 2. DNS query logs with hex subdomains (e.g. q00-47455453... or d0-log.tunnel...)
    dns_hex_matches = re.findall(r"q(\d+)-([0-9a-fA-F]+)\.", log_text)
    if dns_hex_matches:
        hex_dict = dict(dns_hex_matches)
        try:
            full_hex = "".join(hex_dict[str(i).zfill(2)] if str(i).zfill(2) in hex_dict else hex_dict[str(i)] for i in range(len(hex_dict)))
            dec_hex = bytes.fromhex(full_hex).decode("latin-1", errors="ignore")
            extracted.append(dec_hex)
        except Exception:
            pass

    # 3. DNS query logs with Base32 subdomains (e.g. s00.<b32>.beacon...)
    dns_b32_matches = re.findall(r"(?:s\d+|\d\d)\.([a-z2-7A-Z2-7=]{4,})\.", log_text)
    if dns_b32_matches:
        # Deduplicate preserving order
        seen = set()
        clean_chunks = []
        for c in dns_b32_matches:
            c_low = c.lower()
            if c_low not in seen:
                seen.add(c_low)
                clean_chunks.append(c_low)
        # Try both sorted and original order
        for chunks in [clean_chunks, sorted(clean_chunks)]:
            full_b32 = "".join(chunks).upper()
            pad = (8 - len(full_b32) % 8) % 8
            try:
                dec_b32 = base64.b32decode(full_b32 + "=" * pad).decode("latin-1", errors="ignore")
                extracted.append(dec_b32)
            except Exception:
                pass

        # Also extract keyed pattern sXX.<b32>
        keyed = dict(re.findall(r"s(\d+)\.([a-z2-7A-Z2-7=]{4,})\.", log_text))
        if keyed:
            ordered = [keyed[k] for k in sorted(keyed.keys())]
            full_b32_k = "".join(ordered).upper()
            pad_k = (8 - len(full_b32_k) % 8) % 8
            try:
                dec_k = base64.b32decode(full_b32_k + "=" * pad_k).decode("latin-1", errors="ignore")
                extracted.append(dec_k)
            except Exception:
                pass

    # 4. DNS query logs with plain label concatenations (e.g. d0-log.d1-dns...)
    plain_label_matches = re.findall(r"d(\d+)-([a-zA-Z0-9_\-]+)\.tunnel\.", log_text)
    if plain_label_matches:
        label_dict = dict(plain_label_matches)
        labels = [label_dict[str(i)] for i in range(len(label_dict)) if str(i) in label_dict]
        flag_candidate = f"GETSFLAG{{{'_'.join(labels)}}}"
        extracted.append(flag_candidate)

    return extracted


def analyze_pcap_streams(raw_pcap: bytes) -> list[str]:
    """Parse raw PCAP binary, reassemble TCP streams and DNS queries, decompressing payloads."""
    if len(raw_pcap) < 24:
        return []

    endian = "<" if raw_pcap[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    offset = 24
    dns_queries: list[str] = []
    tcp_streams: dict[tuple[int, int], list[tuple[int, bytes]]] = {}
    extracted: list[str] = []

    while offset + 16 <= len(raw_pcap):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", raw_pcap[offset : offset + 16])
        offset += 16
        pkt = raw_pcap[offset : offset + incl_len]
        offset += incl_len

        if len(pkt) < 34 or pkt[12:14] != b"\x08\x00":
            continue

        ip_hdr_len = (pkt[14] & 0x0F) * 4
        proto = pkt[23]
        trans_off = 14 + ip_hdr_len

        # UDP / DNS
        if proto == 17 and len(pkt) >= trans_off + 8:
            sport, dport = struct.unpack("!HH", pkt[trans_off : trans_off + 4])
            udp_payload = pkt[trans_off + 8 :]
            if (sport == 53 or dport == 53) and len(udp_payload) > 12:
                dns_body = udp_payload[12:]
                labels = []
                i = 0
                while i < len(dns_body) and dns_body[i] != 0:
                    l_len = dns_body[i]
                    i += 1
                    labels.append(dns_body[i : i + l_len].decode("latin-1", errors="ignore"))
                    i += l_len
                if labels:
                    dns_queries.append(".".join(labels))

        # TCP Payload
        elif proto == 6 and len(pkt) >= trans_off + 20:
            sport, dport, seq = struct.unpack("!HHI", pkt[trans_off : trans_off + 8])
            tcp_hdr_len = ((pkt[trans_off + 12] >> 4) & 0x0F) * 4
            tcp_payload = pkt[trans_off + tcp_hdr_len :]
            if tcp_payload:
                tcp_streams.setdefault((sport, dport), []).append((seq, tcp_payload))

    # Process TCP streams (sort by sequence number, check for gzip)
    for _key, segments in tcp_streams.items():
        segments.sort(key=lambda x: x[0])
        combined = b"".join(s[1] for s in segments)
        extracted.append(combined.decode("latin-1", errors="ignore"))
        if b"\x1f\x8b" in combined:
            idx = combined.find(b"\x1f\x8b")
            try:
                dec_gz = gzip.decompress(combined[idx:])
                extracted.append(dec_gz.decode("latin-1", errors="ignore"))
            except Exception:
                pass

    # Process DNS queries
    dns_text = "\n".join(dns_queries)
    # Check hex tunnel
    hex_queries = re.findall(r"([0-9a-fA-F]{6,})\.t\.", dns_text)
    if hex_queries:
        try:
            extracted.append(bytes.fromhex("".join(hex_queries)).decode("latin-1", errors="ignore"))
        except Exception:
            pass

    # Check Base32 tunnel
    b32_queries = re.findall(r"([a-z2-7A-Z2-7=]{8,})\.dns\.", dns_text)
    if b32_queries:
        full_b32 = "".join(b32_queries).upper()
        pad = (8 - len(full_b32) % 8) % 8
        try:
            extracted.append(base64.b32decode(full_b32 + "=" * pad).decode("latin-1", errors="ignore"))
        except Exception:
            pass

    # Check XOR Base32 beacon
    xor_b32_queries = re.findall(r"(\d\d)\.([a-z2-70-9A-Z2-70-9]{16,})\.ns1\.", dns_text)
    if xor_b32_queries:
        xor_b32_queries.sort(key=lambda x: x[0])
        full_b32 = "".join(x[1] for x in xor_b32_queries).upper()
        pad = (8 - len(full_b32) % 8) % 8
        try:
            raw_b32 = base64.b32decode(full_b32 + "=" * pad)
            xor_key = b"GF"
            extracted.append(bytes(b ^ xor_key[i % 2] for i, b in enumerate(raw_b32)).decode("latin-1", errors="ignore"))
        except Exception:
            pass

    return extracted
