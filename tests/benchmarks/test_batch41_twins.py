from __future__ import annotations

import base64
import gzip
import io
import struct
import tarfile
import zipfile
import numpy as np
from PIL import Image

from ctf_toolkit.forensics.audio_tools import decode_dual_band_fsk
from ctf_toolkit.forensics.binary_records import assemble_sharded_records_le
from ctf_toolkit.forensics.docx_tools import (
    decode_reversed_hex_vba,
    extract_docx_embeddings,
    repair_docx_broken_header,
)
from ctf_toolkit.forensics.image_channels import (
    extract_bitplane_xor,
    extract_channel_lsb,
    extract_channel_lsb_xor,
    extract_gif_length_prefixed_lsb,
    extract_gif_xor_chunk_stego,
)
from ctf_toolkit.forensics.linux_forensics import decrypt_marker_bounded_xor
from ctf_toolkit.forensics.log_hunter import (
    assemble_dns_b32_exfiltration,
    correlate_multi_log_fragments,
    extract_edr_beacon_sequence,
)
from ctf_toolkit.forensics.memory_tools import assemble_memory_frag_headers, extract_memory_dump_xor
from ctf_toolkit.forensics.pcap_extract import extract_http_basic_auth
from ctf_toolkit.forensics.pdf_tools import extract_pdf_metadata, repair_pdf_broken_header
from ctf_toolkit.forensics.png_tools import (
    extract_png_corrupted_crc_chunks,
    extract_png_trailing_payload,
)
from ctf_toolkit.forensics.zip_recover import (
    decompress_nested_stream,
    extract_cascading_archives,
    fast_zip_crypto_crack,
)
from tests.benchmarks.test_batch39_twins import _make_encrypted_zip


def test_twin_1635_broken_pdf():
    flag = "FLAG{twin_pdf_broken_header}"
    octal_author = "".join(f"\\{ord(c):03o}" for c in flag)
    raw = f"%XDF-1.4\n1 0 obj\n<< /Author ({octal_author}) >>\nendobj\ntrailer\n<<>>\nstartzref\n100\n%%EOF\n".encode("latin-1")
    repaired = repair_pdf_broken_header(raw)
    assert repaired.startswith(b"%PDF-1.4")
    assert b"startxref" in repaired
    meta = extract_pdf_metadata(repaired)
    assert meta.get("Author") == flag


def test_twin_1636_broken_docx_zip():
    flag = "FLAG{twin_docx_broken_zip}"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/document.xml", f"<w:t>{flag}</w:t>")
    data = bytearray(buf.getvalue())
    data[:2] = b"\x00\x00"
    repaired = repair_docx_broken_header(bytes(data))
    zf2 = zipfile.ZipFile(io.BytesIO(repaired))
    assert flag in zf2.read("word/document.xml").decode()


def test_twin_1637_embedded_ole_xlsx():
    flag = b"FLAG{twin_embedded_ole_xlsx}"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/embeddings/oleObject1.xlsx", flag)
    files = extract_docx_embeddings(buf.getvalue())
    assert files.get("oleObject1.xlsx") == flag


def test_twin_1638_reversed_hex_vba():
    flag = b"FLAG{twin_reversed_hex_vba}"
    hex_str = flag.hex()
    reversed_hex = "".join(hex_str[i : i + 2] for i in range(len(hex_str) - 2, -2, -2))
    assert decode_reversed_hex_vba(reversed_hex) == flag


def test_twin_1646_gif_xor_chunks():
    flag = b"FLAG{twin_gif_xor_chunks_hard_01}"
    frames = []
    chunk_size = 4
    for i in range(0, len(flag), chunk_size):
        chunk = flag[i : i + chunk_size]
        frame_idx = i // chunk_size
        key = frame_idx + 1
        arr = np.zeros((10, 10, 3), dtype=np.uint8)
        for c_idx, b in enumerate(chunk):
            arr[0, c_idx, 0] = b ^ key
        frames.append(Image.fromarray(arr))
    buf = io.BytesIO()
    frames[0].save(buf, format="GIF", save_all=True, append_images=frames[1:])
    extracted = extract_gif_xor_chunk_stego(buf.getvalue(), row=0, bytes_per_frame=4)
    assert extracted.startswith(flag)


def test_twin_1648_gif_length_prefixed_lsb():
    flag = b"FLAG{twin_gif_length_prefixed_lsb}"
    f0 = Image.fromarray(np.zeros((10, 10, 3), dtype=np.uint8))
    arr1 = np.zeros((10, 10, 3), dtype=np.uint8)
    flat = arr1[..., 0].flatten()
    flat[0] = len(flag)
    flat[1 : 1 + len(flag)] = list(flag)
    arr1[..., 0] = flat.reshape(arr1[..., 0].shape)
    f1 = Image.fromarray(arr1)

    buf = io.BytesIO()
    f0.save(buf, format="GIF", save_all=True, append_images=[f1])
    extracted = extract_gif_length_prefixed_lsb(buf.getvalue(), frame_idx=1)
    assert extracted == flag


def test_twin_1660_dual_band_fsk():
    flag = b"FLAG{twin_dual_fsk}"
    rate = 8000
    symbol_samples = 400
    samples = []
    t = np.arange(symbol_samples) / rate
    for b in flag:
        high_nib = (b >> 4) & 0x0F
        low_nib = b & 0x0F
        f_low = 500.0 + high_nib * 100.0
        f_high = 2200.0 + low_nib * 100.0
        sig = np.sin(2 * np.pi * f_low * t) + np.sin(2 * np.pi * f_high * t)
        samples.extend(sig)
    arr = np.array(samples, dtype=np.float32)
    dec = decode_dual_band_fsk(arr, rate=rate, symbol_samples=symbol_samples)
    assert dec == flag


def test_twin_1674_png_trailing_zip():
    flag = b"FLAG{twin_png_trailing_zip}"
    buf = io.BytesIO()
    im = Image.new("RGB", (10, 10), "red")
    im.save(buf, format="PNG")
    png_bytes = buf.getvalue()
    payload = b"PK\x03\x04" + flag
    polyglot = png_bytes + payload
    assert extract_png_trailing_payload(polyglot) == payload


def test_twin_1678_png_crc_recompute():
    flag = b"FLAG{twin_png_crc_recompute}"
    buf = io.BytesIO()
    im = Image.new("RGB", (10, 10), "blue")
    im.save(buf, format="PNG")
    png_bytes = bytearray(buf.getvalue())
    custom_chunk = struct.pack(">I4s", len(flag), b"tEXt") + flag + b"\x00\x00\x00\x00"
    iend_pos = png_bytes.find(b"IEND")
    png_bytes = png_bytes[: iend_pos - 4] + custom_chunk + png_bytes[iend_pos - 4 :]
    chunks = extract_png_corrupted_crc_chunks(bytes(png_bytes))
    found = [data for ctype, data in chunks if ctype == b"tEXt" and flag in data]
    assert len(found) > 0


def test_twin_1682_shuffled_le_records():
    flag = b"FLAG{twin_shuffled_le_records}"
    records = []
    for idx, c in enumerate(flag):
        records.append(struct.pack("<Hc", idx, bytes([c])))
    records.reverse()
    blob = b"LREC!\x00" + b"".join(records)
    assert assemble_sharded_records_le(blob) == flag


def test_twin_1701_cascading_archives():
    flag = b"FLAG{twin_cascading_archives}"
    gz_data = gzip.compress(flag)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("inner.gz", gz_data)
    assert extract_cascading_archives(buf.getvalue()) == flag


def test_twin_1702_fast_zip_crypto():
    flag = b"FLAG{twin_zip_crypto_cracked}"
    zip_bytes = _make_encrypted_zip("flag.txt", flag, b"l0veme")
    res = fast_zip_crypto_crack(zip_bytes, [b"wrong", b"l0veme", b"test"])
    assert res is not None
    assert res[0] == b"l0veme"
    assert flag in res[1]


def test_twin_1704_nested_8_layers():
    curr = b"FLAG{twin_nested_8_layers}"
    for _ in range(4):
        curr = gzip.compress(curr)
    assert decompress_nested_stream(curr) == b"FLAG{twin_nested_8_layers}"


def test_twin_1711_lsb_xor_green():
    flag = b"FLAG{twin_lsb_xor_green}"
    xor_flag = bytes(b ^ 0x5A for b in flag)
    bits = np.unpackbits(np.frombuffer(xor_flag, dtype=np.uint8))
    arr = np.zeros((10, len(bits) // 10 + 1, 3), dtype=np.uint8)
    flat_g = arr[..., 1].flatten()
    flat_g[: len(bits)] = bits
    arr[..., 1] = flat_g.reshape(arr[..., 1].shape)
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, format="PNG")
    extracted = extract_channel_lsb_xor(buf.getvalue(), channel="G", bit_pos=0, xor_key=0x5A)
    assert extracted.startswith(flag)


def test_twin_1732_bp_deep():
    flag = b"FLAG{twin_bp_deep_plane3}"
    bits = np.unpackbits(np.frombuffer(flag, dtype=np.uint8))
    arr = np.zeros((10, len(bits) // 10 + 1, 3), dtype=np.uint8)
    flat_b = arr[..., 2].flatten()
    flat_b[: len(bits)] = bits << 3
    arr[..., 2] = flat_b.reshape(arr[..., 2].shape)
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, format="PNG")
    extracted = extract_channel_lsb(buf.getvalue(), channel="B", bit_pos=3)
    assert extracted.startswith(flag)


def test_twin_1741_bp_hunt_unknown():
    flag = b"FLAG{twin_bp_hunt_plane5}"
    bits = np.unpackbits(np.frombuffer(flag, dtype=np.uint8))
    arr = np.zeros((10, len(bits) // 10 + 1, 3), dtype=np.uint8)
    flat_r = arr[..., 0].flatten()
    flat_r[: len(bits)] = bits << 5
    arr[..., 0] = flat_r.reshape(arr[..., 0].shape)
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, format="PNG")
    extracted = extract_channel_lsb(buf.getvalue(), channel="R", bit_pos=5)
    assert extracted.startswith(flag)


def test_twin_1742_bp_hunt_base64():
    raw_flag = b"FLAG{twin_bp_hunt_base64}"
    b64_payload = base64.b64encode(raw_flag)
    bits = np.unpackbits(np.frombuffer(b64_payload, dtype=np.uint8))
    arr = np.zeros((10, len(bits) // 10 + 1, 3), dtype=np.uint8)
    flat_b = arr[..., 2].flatten()
    flat_b[: len(bits)] = bits << 6
    arr[..., 2] = flat_b.reshape(arr[..., 2].shape)
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, format="PNG")
    extracted = extract_channel_lsb(buf.getvalue(), channel="B", bit_pos=6)
    assert base64.b64decode(extracted[: len(b64_payload)]) == raw_flag


def test_twin_1743_bp_xor_two_planes():
    flag = b"FLAG{twin_bp_xor_planes}"
    bits = np.unpackbits(np.frombuffer(flag, dtype=np.uint8))
    arr = np.zeros((10, len(bits) // 10 + 1, 3), dtype=np.uint8)
    flat_b = arr[..., 2].flatten()
    flat_b[: len(bits)] = (1 << 1) | ((bits ^ 1) << 3)
    arr[..., 2] = flat_b.reshape(arr[..., 2].shape)
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, format="PNG")
    extracted = extract_bitplane_xor(buf.getvalue(), channel="B", plane_a=1, plane_b=3)
    assert extracted.startswith(flag)


def test_twin_1756_xor_dropper_elf():
    flag = "FLAG{twin_xor_dropper_elf}"
    enc = bytes(ord(c) ^ 0x5A for c in flag)
    blob = b"DUMMY_ELF_HEADER_XK" + enc + b"XK_DUMMY_TRAILER"
    matches = decrypt_marker_bounded_xor(blob, key=0x5A)
    assert flag in matches


def test_twin_1761_memory_split_regions():
    p1 = b"FLAG{twin_mem_split_"
    p2 = b"two_regions}"
    off1, off2 = 50, 120
    len1, len2 = len(p1), len(p2)
    buf = bytearray(200)
    buf[:8] = b"FRAGHDR\x00"
    buf[8:24] = struct.pack("<IIII", off1, off2, len1, len2)
    buf[off1 : off1 + len1] = p1
    buf[off2 : off2 + len2] = p2
    assert assemble_memory_frag_headers(bytes(buf)) == p1 + p2


def test_twin_1763_memory_heap_xor():
    flag = "FLAG{twin_memory_heap_xor}"
    enc = bytes(ord(c) ^ 0x3C for c in flag)
    blob = b"\x00" * 30 + enc + b"\x00" * 30
    matches = extract_memory_dump_xor(blob, key=0x3C)
    assert flag in matches


def test_twin_1786_dns_b32_exfil():
    flag = b"FLAG{twin_dns_b32_exfil}"
    b32 = base64.b32encode(flag).decode().rstrip("=")
    chunk1, chunk2 = b32[: len(b32) // 2], b32[len(b32) // 2 :]
    log = f"query[A] s00.{chunk1}.beacon.c2-shadowfox.ru\nquery[A] s01.{chunk2}.beacon.c2-shadowfox.ru\n"
    assert assemble_dns_b32_exfiltration(log) == flag


def test_twin_1787_tri_log_fragments():
    flag = "FLAG{twin_tri_log_fragments}"
    b64 = base64.b64encode(flag.encode()).decode()
    parts = [b64[0:10], b64[10:20], b64[20:]]
    logs = [
        f"event: auth XFRAG=0:{parts[0]}",
        f"event: audit XFRAG=1:{parts[1]}",
        f"event: app XFRAG=2:{parts[2]}",
    ]
    assert correlate_multi_log_fragments(logs) == flag


def test_twin_1788_edr_perline_byte():
    flag = "FLAG{twin_edr_perline_byte}"
    lines = [f"telem[42]: hb seq={i:03d} size={ord(c)}" for i, c in enumerate(flag)]
    assert extract_edr_beacon_sequence("\n".join(lines)) == flag


def test_twin_1798_net_basic_auth():
    flag = "FLAG{twin_net_basic_auth}"
    cred = f"admin:{flag}"
    b64_cred = base64.b64encode(cred.encode()).decode()
    packet = f"GET /admin HTTP/1.1\r\nAuthorization: Basic {b64_cred}\r\n\r\n".encode()
    creds = extract_http_basic_auth(packet)
    assert any(flag in c for c in creds)
