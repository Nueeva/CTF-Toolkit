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
