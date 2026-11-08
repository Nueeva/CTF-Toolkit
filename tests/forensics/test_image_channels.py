import io
from PIL import Image
from ctf_toolkit.forensics.image_channels import extract_channel_bytes, find_flags_in_channel


def test_extract_channel_bytes():
    # Create 2x2 synthetic RGB image
    # Red: [65, 66, 67, 68] ('ABCD')
    # Green: [0, 0, 0, 0]
    # Blue: [0, 0, 0, 0]
    im = Image.new("RGB", (2, 2))
    im.putdata([(65, 0, 0), (66, 0, 0), (67, 0, 0), (68, 0, 0)])

    buf = io.BytesIO()
    im.save(buf, format="PNG")
    raw_img = buf.getvalue()

    r_bytes = extract_channel_bytes(raw_img, "R")
    assert r_bytes == b"ABCD"


def test_find_flags_in_channel():
    flag = b"GETSFLAG{channel_red}"
    # Create image of width len(flag) and height 1
    im = Image.new("RGB", (len(flag), 1))
    pixels = [(b, 128, 128) for b in flag]
    im.putdata(pixels)

    buf = io.BytesIO()
    im.save(buf, format="PNG")
    raw_img = buf.getvalue()

    flags = find_flags_in_channel(raw_img, "R")
    assert flags == ["GETSFLAG{channel_red}"]
