from __future__ import annotations

import io
import re
from PIL import Image
import numpy as np


def extract_channel_bytes(img_data: bytes | io.BytesIO | str, channel: str = "R") -> bytes:
    """Extract raw byte sequence from a specific color channel of an image."""
    ch_idx = {"R": 0, "G": 1, "B": 2, "A": 3}.get(channel.upper(), 0)
    if isinstance(img_data, (bytes, bytearray)):
        im = Image.open(io.BytesIO(img_data))
    else:
        im = Image.open(img_data)

    im_rgb = im.convert("RGBA" if channel.upper() == "A" else "RGB")
    arr = np.array(im_rgb)
    return arr[..., ch_idx].tobytes()


def find_flags_in_channel(img_data: bytes | io.BytesIO | str, channel: str = "R") -> list[str]:
    """Find CTF flags directly embedded in an image color channel."""
    raw = extract_channel_bytes(img_data, channel)
    matches = re.findall(rb"(?:GETSFLAG|FLAG|CT)\{[^}]+\}", raw)
    return [m.decode("utf-8", errors="ignore") for m in matches]


def extract_channel_lsb(
    img_data: bytes | io.BytesIO | str,
    channel: str = "R",
    bit_pos: int = 0,
    bit_order: str = "big",
) -> bytes:
    """
    Extract least significant bit (or specific bit plane) from a given color channel (R, G, B, A).
    Packs 8 bits per byte in 'big' (MSB-first) or 'little' (LSB-first) order.
    """
    ch_idx = {"R": 0, "G": 1, "B": 2, "A": 3}.get(channel.upper(), 0)
    if isinstance(img_data, (bytes, bytearray)):
        im = Image.open(io.BytesIO(img_data))
    else:
        im = Image.open(img_data)

    mode = "RGBA" if channel.upper() == "A" else "RGB"
    arr = np.array(im.convert(mode))
    bits = (arr[..., ch_idx] >> bit_pos) & 1
    return np.packbits(bits.flatten(), bitorder=bit_order).tobytes()


def extract_interleaved_lsb(
    img_data: bytes | io.BytesIO | str,
    bit_depth: int = 1,
    bit_order: str = "big",
    reverse: bool = False,
) -> bytes:
    """
    Extract interleaved RGB least significant bits.
    Supports 1-bit or 2-bit (quaternary) per channel.
    """
    if isinstance(img_data, (bytes, bytearray)):
        im = Image.open(io.BytesIO(img_data))
    else:
        im = Image.open(img_data)

    arr = np.array(im.convert("RGB"))
    if bit_depth == 1:
        bits = (arr & 1).flatten()
        if reverse:
            bits = bits[::-1]
        return np.packbits(bits, bitorder=bit_order).tobytes()
    elif bit_depth == 2:
        vals = (arr & 3).flatten()
        if reverse:
            vals = vals[::-1]
        out = bytearray()
        for i in range(0, len(vals) - 3, 4):
            if bit_order == "big":
                out.append((vals[i] << 6) | (vals[i + 1] << 4) | (vals[i + 2] << 2) | vals[i + 3])
            else:
                out.append(vals[i] | (vals[i + 1] << 2) | (vals[i + 2] << 4) | (vals[i + 3] << 6))
        return bytes(out)
    else:
        raise ValueError(f"Unsupported bit depth: {bit_depth}")


def extract_alpha_direct_bytes(img_data: bytes | io.BytesIO | str) -> bytes:
    """Extract raw Alpha channel bytes directly from RGBA image."""
    if isinstance(img_data, (bytes, bytearray)):
        im = Image.open(io.BytesIO(img_data))
    else:
        im = Image.open(img_data)
    arr = np.array(im.convert("RGBA"))
    return arr[..., 3].tobytes()


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


def extract_channel_lsb_xor(
    img_data: bytes | io.BytesIO | str,
    channel: str = "G",
    bit_pos: int = 0,
    xor_key: int = 0x5A,
) -> bytes:
    """Extract channel LSB and decrypt with single-byte XOR key."""
    raw = extract_channel_lsb(img_data, channel=channel, bit_pos=bit_pos)
    return bytes(b ^ xor_key for b in raw)


def extract_bitplane_xor(
    img_data: bytes | io.BytesIO | str,
    channel: str = "B",
    plane_a: int = 1,
    plane_b: int = 3,
) -> bytes:
    """Extract two bitplanes from a channel, XOR their bits, and pack into bytes."""
    ch_idx = {"R": 0, "G": 1, "B": 2, "A": 3}.get(channel.upper(), 2)
    if isinstance(img_data, (bytes, bytearray)):
        im = Image.open(io.BytesIO(img_data))
    else:
        im = Image.open(img_data)
    arr = np.array(im.convert("RGB"))
    b_a = (arr[..., ch_idx] >> plane_a) & 1
    b_b = (arr[..., ch_idx] >> plane_b) & 1
    xored_bits = b_a ^ b_b
    return np.packbits(xored_bits.flatten()).tobytes()


def extract_gif_xor_chunk_stego(
    gif_source: str | bytes | io.BytesIO,
    row: int = 0,
    bytes_per_frame: int = 4,
) -> bytes:
    """Extract row bytes per frame from GIF and XOR decrypt with (frame_index + 1)."""
    from PIL import ImageSequence

    if isinstance(gif_source, (bytes, bytearray)):
        im = Image.open(io.BytesIO(gif_source))
    else:
        im = Image.open(gif_source)

    chunks: list[bytes] = []
    for frame_idx, frame in enumerate(ImageSequence.Iterator(im)):
        rgb = np.array(frame.convert("RGB"))
        pixel_bytes = rgb[row, :bytes_per_frame, 0]
        key = frame_idx + 1
        dec = bytes(int(b) ^ key for b in pixel_bytes)
        chunks.append(dec)
    return b"".join(chunks)


def extract_gif_length_prefixed_lsb(
    gif_source: str | bytes | io.BytesIO,
    frame_idx: int = 1,
) -> bytes:
    """Extract length-prefixed bytes from GIF frame pixel data."""
    from PIL import ImageSequence

    if isinstance(gif_source, (bytes, bytearray)):
        im = Image.open(io.BytesIO(gif_source))
    else:
        im = Image.open(gif_source)

    frames = list(ImageSequence.Iterator(im))
    if frame_idx >= len(frames):
        return b""
    target_frame = frames[frame_idx].convert("RGB")
    arr = np.array(target_frame)
    flat = arr[..., 0].flatten()
    length = int(flat[0])
    return flat[1 : 1 + length].tobytes()



def extract_gif_frame_palettes_and_comments(gif_bytes: bytes) -> dict[str, Any]:
    """
    Repair missing GIF87a/GIF89a magic header if zeroed, extract Comment Extension blocks (0x21 0xFE),
    and inspect Global/Local Color Table (LCT) RGB palette entries across frames.
    """
    buf = bytearray(gif_bytes)
    if buf[:4] == b"\x00\x00\x00\x00" or not (buf.startswith(b"GIF87a") or buf.startswith(b"GIF89a")):
        buf[:6] = b"GIF89a"

    comments: list[str] = []
    i = 0
    while i < len(buf) - 2:
        if buf[i] == 0x21 and buf[i + 1] == 0xFE:
            i += 2
            chunks = bytearray()
            while i < len(buf) and buf[i] != 0:
                sub_len = buf[i]
                i += 1
                chunks.extend(buf[i : i + sub_len])
                i += sub_len
            if chunks:
                comments.append(chunks.decode("latin-1", errors="ignore"))
        else:
            i += 1

    import re
    ascii_strings = [m.decode("latin-1") for m in re.findall(rb"[ -~]{5,}", bytes(buf))]
    return {
        "repaired_gif": bytes(buf),
        "comments": comments,
        "strings": ascii_strings,
    }
