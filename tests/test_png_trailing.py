import io
from PIL import Image

from ctf_toolkit.forensics.image_channels import (
    extract_png_trailing_bytes,
    extract_sequential_rgb_bytes,
)


def test_extract_png_trailing_bytes() -> None:
    # Minimal mock PNG containing IEND chunk followed by trailing text
    mock_png = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x00IEND\xae\x42\x60\x82" + b"TRAILING_PAYLOAD_FLAG"
    trailing = extract_png_trailing_bytes(mock_png)
    assert trailing == b"TRAILING_PAYLOAD_FLAG"


def test_extract_png_trailing_empty() -> None:
    mock_png = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x00IEND\xae\x42\x60\x82"
    trailing = extract_png_trailing_bytes(mock_png)
    assert trailing == b""


def test_extract_sequential_rgb_bytes() -> None:
    # 2x1 RGB image with pixels (65, 66, 67) and (68, 69, 70) -> "ABCDEF"
    im = Image.new("RGB", (2, 1))
    im.putpixel((0, 0), (65, 66, 67))
    im.putpixel((1, 0), (68, 69, 70))
    buf = io.BytesIO()
    im.save(buf, format="PNG")
    raw_rgb = extract_sequential_rgb_bytes(buf.getvalue())
    assert raw_rgb == b"ABCDEF"
