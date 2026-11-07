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

def decode_qr_image(img_data: bytes | io.BytesIO | str | Image.Image) -> list[str]:
    """
    Decode QR codes from an image, scanning multiple orientations (0, 90, 180, 270 degrees)
    and horizontal flips to recover rotated or mirrored barcodes.
    """
    import numpy as np

    try:
        import cv2
    except ImportError:
        return []

    if isinstance(img_data, Image.Image):
        im = img_data
    elif isinstance(img_data, (bytes, bytearray)):
        im = Image.open(io.BytesIO(img_data))
    elif isinstance(img_data, io.BytesIO):
        im = Image.open(img_data)
    else:
        im = Image.open(img_data)

    detector = cv2.QRCodeDetector()
    results: list[str] = []

    for flip in [False, True]:
        base_im = im.transpose(Image.FLIP_LEFT_RIGHT) if flip else im
        for angle in [0, 90, 180, 270]:
            rot = base_im.rotate(angle, expand=True) if angle else base_im
            arr = cv2.cvtColor(np.array(rot.convert("RGB")), cv2.COLOR_RGB2BGR)
            for border in [0, 20, 40]:
                curr = (
                    cv2.copyMakeBorder(arr, border, border, border, border, cv2.BORDER_CONSTANT, value=[255, 255, 255])
                    if border > 0
                    else arr
                )
                val, pts, _ = detector.detectAndDecode(curr)
                if val and val not in results:
                    results.append(val)
                    break

    return results

def extract_gif_scanline_bits(gif_source: str | bytes | io.BytesIO) -> list[str]:
    """
    Extract embedded binary scanlines from animated GIF frames.
    Finds frames with bi-level pixel rows at edges (e.g. rows 0 and 1) and reconstructs ASCII strings.
    """
    from PIL import ImageSequence

    if isinstance(gif_source, (bytes, bytearray)):
        im = Image.open(io.BytesIO(gif_source))
    elif isinstance(gif_source, io.BytesIO):
        im = Image.open(gif_source)
    else:
        im = Image.open(gif_source)

    recovered: list[str] = []
    for frame_idx, frame in enumerate(ImageSequence.Iterator(im)):
        rgb = frame.convert("RGB")
        w, h = rgb.size
        # Overall frame background from bottom corner
        bg_color = rgb.getpixel((0, h - 1))

        bit_accum = ""
        for y in range(min(4, h)):
            row = [rgb.getpixel((x, y)) for x in range(w)]
            unique_colors = set(row)
            if len(unique_colors) == 2 and bg_color in unique_colors:
                bits = "".join(["0" if p == bg_color else "1" for p in row])
                bit_accum += bits

        if len(bit_accum) >= 64:
            for inv in [False, True]:
                b_str = "".join(["1" if b == "0" else "0" for b in bit_accum]) if inv else bit_accum
                dec = bytes([int(b_str[i : i + 8], 2) for i in range(0, len(b_str) - len(b_str) % 8, 8)])
                text = dec.decode("latin1", errors="ignore").strip("\x00 ")
                if text and text not in recovered:
                    recovered.append(text)

    return recovered

