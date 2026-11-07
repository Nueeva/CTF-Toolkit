from __future__ import annotations

import base64
import gzip
import io
import re
import struct

from ctf_toolkit.crypto.classical import repeating_key_xor
from ctf_toolkit.forensics.network_artifacts import (
    assemble_icmp_echo_payloads,
    decode_dns_xor_b32_beacon,
    extract_dns_base32_subdomains,
    extract_dns_hex_subdomains,
    reassemble_tcp_stream_seq,
)
from ctf_toolkit.reversing.transforms import (
    byte_shift,
    extract_binary_strings,
    invert_bitwise_not,
    invert_index_sub,
    invert_index_xor,
    invert_scaled_index_xor,
    invert_scaled_linear_add,
    rotate_byte_right,
    xor_bytes,
)


def _make_dummy_pcap(packets: list[tuple[int, bytes]]) -> bytes:
    """Helper to synthesize simple PCAP bytes with Ethernet/IP headers."""
    # PCAP Global Header (24 bytes)
    hdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    pkts = bytearray()
    for proto, payload in packets:
        # Construct IP pkt
        if proto == 1:  # ICMP
            trans_hdr = struct.pack(">BBHI", 8, 0, 0, 0)
            ip_data = trans_hdr + payload
            ip_hdr = struct.pack(">BBHHHBBHII", 0x45, 0, 20 + len(ip_data), 1, 0, 64, 1, 0, 0x7F000001, 0x7F000002)
        elif proto == 6:  # TCP
            # seq = 100
            trans_hdr = struct.pack(">HHI", 1234, 8080, 100) + b"\x50\x18\x20\x00\x00\x00\x00\x00"
            ip_data = trans_hdr + payload
            ip_hdr = struct.pack(">BBHHHBBHII", 0x45, 0, 20 + len(ip_data), 1, 0, 64, 6, 0, 0x7F000001, 0x7F000002)
        else:
            ip_data = payload
            ip_hdr = struct.pack(">BBHHHBBHII", 0x45, 0, 20 + len(ip_data), 1, 0, 64, proto, 0, 0x7F000001, 0x7F000002)

        eth_hdr = struct.pack(">6s6sH", b"\x00" * 6, b"\x00" * 6, 0x0800)
        full_frame = eth_hdr + ip_hdr + ip_data
        pkt_hdr = struct.pack("<IIII", 1000, 0, len(full_frame), len(full_frame))
        pkts.extend(pkt_hdr + full_frame)
    return bytes(hdr + pkts)


def test_twin_1799_net_dns_hex_exfil():
    flag = b"FLAG{twin_net_dns_hex_exfil}"
    hex_str = flag.hex()
    pcap_data = (
        b"\xd4\xc3\xb2\xa1"
        + b"\x00" * 20
        + b"prefix."
        + hex_str[:20].encode()
        + b".t.evil-dns.id"
        + b"..."
        + hex_str[20:].encode()
        + b".t.evil-dns.id"
    )
    assert extract_dns_hex_subdomains(pcap_data, domain_suffix="evil-dns.id") == flag


def test_twin_1800_net_ftp_retr_data():
    flag = "FLAG{twin_net_ftp_retr_data}"
    blob = f"USER kurir\r\nPASS logistik\r\nRETR data.csv\r\naccess_code={flag}\r\n".encode()
    found = re.search(rb"FLAG\{[^}]+\}", blob).group(0).decode()
    assert found == flag


def test_twin_1801_net_icmp_echo_exfil():
    flag = b"FLAG{twin_net_icmp_echo_exfil}"
    packets = []
    for i in range(0, len(flag), 4):
        chunk = flag[i : i + 4]
        packets.append((1, b"\x08" + chunk))
    pcap = _make_dummy_pcap(packets)
    assert assemble_icmp_echo_payloads(pcap) == flag


def test_twin_1802_net_tcp_stream_reasm():
    flag = "FLAG{twin_net_tcp_stream_reasm}"
    p1 = "payload-start||FLAG{twin_net_tcp_"
    p2 = "stream_reasm}||payload-end"
    reassembled = p1 + p2
    m = re.search(r"FLAG\{[^}]+\}", reassembled)
    assert m and m.group(0) == flag


def test_twin_1803_net_img_append_carve():
    flag = b"FLAG{twin_net_img_append_carve}"
    png_dummy = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x00IEND\xaeB`\x82" + flag
    m = re.search(rb"FLAG\{[^}]+\}", png_dummy)
    assert m and m.group(0) == flag


def test_twin_1804_net_json_b64_body():
    flag = "FLAG{twin_net_json_b64_body}"
    b64_val = base64.b64encode(flag.encode()).decode()
    raw = f'{{"event":"backup","payload":"{b64_val}"}}'.encode()
    m = re.search(rb'"payload":\s*"([A-Za-z0-9+/=]+)"', raw)
    assert m and base64.b64decode(m.group(1)).decode() == flag


def test_twin_1805_net_dns_base32_exfil():
    flag = b"FLAG{twin_net_dns_base32_exfil}"
    b32_str = base64.b32encode(flag).decode().rstrip("=")
    pcap_data = (
        b"\xd4\xc3\xb2\xa1"
        + b"\x00" * 20
        + b"query: "
        + b32_str[:16].encode()
        + b".dns.exfil-c2.net"
        + b" query: "
        + b32_str[16:].encode()
        + b".dns.exfil-c2.net"
    )
    assert extract_dns_base32_subdomains(pcap_data, domain_suffix="exfil-c2.net") == flag


def test_twin_1806_net_dns_xor_b32_hard():
    flag = b"FLAG{twin_dns_xor_b32_hard_01}"
    key = b"GF"
    xor_flag = bytes(b ^ key[i % len(key)] for i, b in enumerate(flag))
    b32 = base64.b32encode(xor_flag).decode()
    mid = len(b32) // 2
    c0 = b32[:mid].lower()
    c1 = b32[mid:].lower()
    pcap_data = (
        b"\xd4\xc3\xb2\xa1"
        + b"\x00" * 20
        + b"00"
        + c0.encode()
        + b".ns1.telemetry-hub.io"
        + b" ... 01"
        + c1.encode()
        + b".ns1.telemetry-hub.io"
    )
    assert decode_dns_xor_b32_beacon(pcap_data, domain_suffix="telemetry-hub.io", xor_key=b"GF") == flag


def test_twin_1807_net_tcp_ooo_gzip():
    flag = "FLAG{twin_net_tcp_ooo_gzip}"
    gz = gzip.compress(flag.encode())
    half = len(gz) // 2
    p1 = gz[:half]
    p2 = gz[half:]

    # Construct out of order TCP packets in PCAP
    hdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    def make_pkt(seq, payload):
        ip_data = struct.pack(">HHI", 8080, 1234, seq) + b"\x00" * 4 + b"\x50\x18\x20\x00\x00\x00\x00\x00" + payload
        ip_hdr = struct.pack(">BBHHHBBHII", 0x45, 0, 20 + len(ip_data), 1, 0, 64, 6, 0, 0x7F000001, 0x7F000002)
        eth_hdr = struct.pack(">6s6sH", b"\x00" * 6, b"\x00" * 6, 0x0800)
        full = eth_hdr + ip_hdr + ip_data
        return struct.pack("<IIII", 1000, 0, len(full), len(full)) + full

    # Feed p2 before p1
    pcap = hdr + make_pkt(200, p2) + make_pkt(100, p1)
    reordered = reassemble_tcp_stream_seq(pcap, filter_port=8080)
    assert gzip.decompress(reordered).decode() == flag


def test_twin_1808_net_png_text_multiseg():
    flag = "FLAG{twin_net_png_text_multiseg}"
    data = f"tEXtComment\x00{flag}\x00\x00\x00\x00IEND".encode()
    m = re.search(r"FLAG\{[^}]+", data.decode("latin-1"))
    assert m and (m.group(0) + "}") == flag


def test_twin_12_hardcoded_keys_leak():
    flag = "FLAG{twin_hardcoded_keys_leak}"
    binary = b"\x7fELF" + b"\x00" * 100 + flag.encode() + b"\x00" * 50
    strings = extract_binary_strings(binary, pattern=r"FLAG\{")
    assert flag in strings


def test_twin_169_index_matters():
    flag = b"FLAG{twin_index_matters}"
    target = bytes(b ^ i for i, b in enumerate(flag))
    assert invert_index_xor(target) == flag


def test_twin_170_repeating_key_rc():
    flag = b"FLAG{twin_repeating_key_rc}"
    key = b"heat"
    target = bytes(b ^ key[i % len(key)] for i, b in enumerate(flag))
    assert repeating_key_xor(target, key) == flag


def test_twin_171_minus_index():
    flag = b"FLAG{twin_minus_index}"
    target = bytes((b - i) & 0xFF for i, b in enumerate(flag))
    assert invert_index_sub(target) == flag


def test_twin_172_bitwise_not():
    flag = b"FLAG{twin_bitwise_not}"
    target = bytes((~b) & 0xFF for b in flag)
    assert invert_bitwise_not(target) == flag


def test_twin_173_constant_add():
    flag = b"FLAG{twin_constant_add}"
    target = byte_shift(flag, 0x10)
    assert byte_shift(target, -0x10) == flag


def test_twin_174_rotate_bits():
    flag = b"FLAG{twin_rotate_bits}"
    # Rotate left 3 bits
    target = bytes(((b << 3) | (b >> 5)) & 0xFF for b in flag)
    assert rotate_byte_right(target, shift=3) == flag


def test_twin_175_feedback_xor():
    flag = b"FLAG{twin_feedback_xor}"
    # Target: (7 * i) ^ flag ^ 0x5A
    target = bytes(((7 * i) & 0xFF) ^ b ^ 0x5A for i, b in enumerate(flag))
    assert invert_scaled_index_xor(target, scale=7, xor_key=0x5A) == flag


def test_twin_176_linear_add():
    flag = b"FLAG{twin_linear_add}"
    target = bytes((b + 3 * i) & 0xFF for i, b in enumerate(flag))
    assert invert_scaled_linear_add(target, scale=3) == flag


def test_twin_177_single_xor():
    flag = b"FLAG{twin_single_xor}"
    target = xor_bytes(flag, 0xC3)
    assert xor_bytes(target, 0xC3) == flag


def test_twin_186_python_bytecode():
    flag = b"FLAG{twin_python_bytecode}"
    key = 7
    target = [b ^ key for b in flag]
    assert bytes(b ^ key for b in target) == flag


def test_twin_187_marshal_magic():
    flag = b"FLAG{twin_marshal_magic}"
    key = 8
    target = [b ^ key for b in flag]
    assert bytes(b ^ key for b in target) == flag


def test_twin_188_dis_the_code():
    flag = b"FLAG{twin_dis_the_code}"
    key = 9
    target = [b ^ key for b in flag]
    assert bytes(b ^ key for b in target) == flag


def test_twin_189_pyc_header():
    flag = b"FLAG{twin_pyc_header}"
    key = 10
    target = [b ^ key for b in flag]
    assert bytes(b ^ key for b in target) == flag


def test_twin_190_obfuscated_bash():
    flag = "FLAG{twin_obfuscated_bash}"
    b64 = base64.b64encode(flag.encode()).decode()
    sh_content = f'#!/bin/bash\nD=$(echo {b64} | base64 -d)\n'
    m = re.search(r"echo\s+([A-Za-z0-9+/=]+)", sh_content)
    assert m and base64.b64decode(m.group(1)).decode() == flag
