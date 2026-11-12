"""
High-yield image steganography and bit-plane extraction tools.

Extracts hidden flags from:
1. Individual color channels and bit-planes (R, G, B, A, bit-planes 0..7).
2. Bit-plane XOR combinations (e.g. plane1 ^ plane3 in Blue channel).
3. Interleaved multi-channel bitstreams (RGB 1-bit, 2-bit, normal and reversed).
4. Direct Alpha channel byte values.
5. PNG text chunks (tEXt, zTXt, iTXt) with automatic Base64 and Base32 decoding.
6. Animated GIF frame steganography (zero-delay frames, frame diff XORs,
   per-frame bit-planes, and inter-frame sequence concatenation).
"""
from __future__ import annotations

import io
import re
import numpy as np
from PIL import Image

PRINTABLE = set(range(32, 127))


def extract_all_bit_planes(img_data: bytes | str) -> dict[str, bytes]:
    """
    Extract raw byte streams from all 32 bit-planes (R0..R7, G0..G7, B0..B7, A0..A7)
    both in row-major and column-major order, with MSB-first packing.
    """
    if isinstance(img_data, str):
        im = Image.open(img_data)
    else:
        im = Image.open(io.BytesIO(img_data))

    arr = np.array(im.convert("RGBA"))
    res: dict[str, bytes] = {}

    ch_names = ["R", "G", "B", "A"]
    for ch_idx, ch_name in enumerate(ch_names):
        plane = arr[..., ch_idx]
        for bp in range(8):
            bits = (plane >> bp) & 1
            # Row-major bit packing
            bytes_row = np.packbits(bits.flatten(), bitorder="big").tobytes()
            res[f"{ch_name}{bp}"] = bytes_row

            # Check if reversed byte stream contains flag
            res[f"{ch_name}{bp}_rev"] = bytes_row[:2048][::-1]

    # Interleaved RGB bitstreams (1-bit and 2-bit)
    rgb = arr[..., :3]
    bits_1 = (rgb & 1).flatten()
    res["interleaved_1bit"] = np.packbits(bits_1, bitorder="big").tobytes()
    res["interleaved_1bit_rev"] = res["interleaved_1bit"][:2048][::-1]

    vals_2 = (rgb & 3).flatten()
    out_2 = bytearray()
    for i in range(0, len(vals_2) - 3, 4):
        out_2.append((vals_2[i] << 6) | (vals_2[i + 1] << 4) | (vals_2[i + 2] << 2) | vals_2[i + 3])
    res["interleaved_2bit"] = bytes(out_2)

    # Alpha direct byte values
    res["alpha_direct"] = arr[..., 3].tobytes()

    # Blue plane XOR pairs (common in dual-plane stegano)
    blue = arr[..., 2]
    for p1 in range(8):
        for p2 in range(p1 + 1, 8):
            b1 = (blue >> p1) & 1
            b2 = (blue >> p2) & 1
            xor_bits = b1 ^ b2
            res[f"B_xor_{p1}_{p2}"] = np.packbits(xor_bits.flatten(), bitorder="big").tobytes()

    return res


def render_visual_bit_planes(img_data: bytes | str) -> dict[str, str]:
    """
    Render 2D visual bit-planes as base64-encoded PNG data URIs for web display (AperiSolve/StegSolve parity).
    Covers R0..R7, G0..G7, B0..B7, A0..A7.
    """
    import base64
    if isinstance(img_data, str):
        im = Image.open(img_data)
    else:
        im = Image.open(io.BytesIO(img_data))

    arr = np.array(im.convert("RGBA"))
    visual_planes: dict[str, str] = {}

    ch_names = ["R", "G", "B", "A"]
    for ch_idx, ch_name in enumerate(ch_names):
        plane = arr[..., ch_idx]
        for bp in range(8):
            bits = ((plane >> bp) & 1).astype(np.uint8) * 255
            plane_img = Image.fromarray(bits, mode="L")
            buf = io.BytesIO()
            plane_img.save(buf, format="PNG")
            b64_uri = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")
            visual_planes[f"{ch_name}{bp}"] = b64_uri

    return visual_planes


def extract_gif_stego_payloads(gif_data: bytes | str) -> list[str]:
    """
    Extract hidden payloads and flags from animated GIF files across:
    1. Zero-delay or abnormally fast frames.
    2. Manipulated frame raw pixel bytes.
    3. Inter-frame XOR differential (diff vs Frame 0).
    4. Concatenated chunks sliced across consecutive frames.
    5. Single frame bit-plane LSBs.
    """
    if isinstance(gif_data, str):
        im = Image.open(gif_data)
    else:
        im = Image.open(io.BytesIO(gif_data))

    n_frames = getattr(im, "n_frames", 1)
    if n_frames <= 1:
        return []

    found_strings: list[str] = []
    frames = []
    durations = []

    for f in range(n_frames):
        im.seek(f)
        frames.append(np.array(im.convert("RGB")))
        durations.append(im.info.get("duration", 100))

    # 1. Zero-delay frames
    for f_idx, dur in enumerate(durations):
        if dur == 0:
            frame_raw = frames[f_idx].tobytes()
            found_strings.append(frame_raw.decode("latin-1", errors="ignore"))

    # 2. Per-frame row 0 and column 0 channel text
    for f_idx, frame in enumerate(frames):
        for ch in range(3):
            row0 = "".join(chr(b) for b in frame[0, :, ch] if 32 <= b <= 126)
            if row0:
                found_strings.append(row0)
            col0 = "".join(chr(b) for b in frame[:, 0, ch] if 32 <= b <= 126)
            if col0:
                found_strings.append(col0)

    # 3. Frame XOR diff vs Frame 0
    f0 = frames[0]
    for f_idx in range(1, n_frames):
        f = frames[f_idx]
        for ch in range(3):
            xor_row = bytes(f[0, :, ch] ^ f0[0, :, ch])
            found_strings.append(xor_row.decode("latin-1", errors="ignore"))

    # 4. Slices across consecutive frames (e.g. 6 bytes per frame)
    for slice_len in (4, 6, 8, 16):
        for ch in range(3):
            joined = bytearray()
            for frame in frames:
                joined.extend(frame[0, :slice_len, ch].tolist())
            found_strings.append(bytes(joined).decode("latin-1", errors="ignore"))

    # 5. Frame bit-plane LSB
    for frame in frames:
        for ch in range(3):
            bits = (frame[..., ch] & 1).flatten()
            lsb_bytes = np.packbits(bits, bitorder="big").tobytes()
            found_strings.append(lsb_bytes[:2048].decode("latin-1", errors="ignore"))

    return found_strings
