from __future__ import annotations

import io
import re
from PIL import Image


def extract_channel_bytes(img_data: bytes | io.BytesIO | str, channel: str = "R") -> bytes:
    """Extract raw byte sequence from a specific color channel of an image."""
    ch_idx = {"R": 0, "G": 1, "B": 2, "A": 3}.get(channel.upper(), 0)
    if isinstance(img_data, (bytes, bytearray)):
        im = Image.open(io.BytesIO(img_data))
    else:
        im = Image.open(img_data)

    im_rgb = im.convert("RGBA" if channel.upper() == "A" else "RGB")
    pixels = list(im_rgb.getdata())
    return bytes([p[ch_idx] for p in pixels])


def find_flags_in_channel(img_data: bytes | io.BytesIO | str, channel: str = "R") -> list[str]:
    """Find CTF flags directly embedded in an image color channel."""
    raw = extract_channel_bytes(img_data, channel)
    matches = re.findall(rb"(?:GETSFLAG|CT)\{[^}]+\}", raw)
    return [m.decode("utf-8", errors="ignore") for m in matches]


def extract_png_trailing_bytes(img_data: bytes | str) -> bytes:
    """
    Extract trailing data appended past the PNG IEND chunk (EOF).
    In standard PNG, data past IEND + 8 bytes (chunk name + 4-byte CRC)
    is ignored by standard decoders but frequently conceals hidden payloads.
    """
    if isinstance(img_data, str):
        with open(img_data, "rb") as f:
            raw = f.read()
    else:
        raw = bytes(img_data)

    idx = raw.rfind(b"IEND")
    if idx == -1:
        return b""
    return raw[idx + 8 :]


def extract_sequential_rgb_bytes(img_data: bytes | io.BytesIO | str) -> bytes:
    """
    Extract raw bytes formed by concatenating RGB pixel channels sequentially
    (R0, G0, B0, R1, G1, B1, ...) across the image.
    """
    if isinstance(img_data, (bytes, bytearray)):
        im = Image.open(io.BytesIO(img_data))
    elif isinstance(img_data, io.BytesIO):
        im = Image.open(img_data)
    else:
        im = Image.open(img_data)

    im_rgb = im.convert("RGB")
    return im_rgb.tobytes()

