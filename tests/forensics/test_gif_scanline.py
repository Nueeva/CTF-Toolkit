import io
from PIL import Image
from ctf_toolkit.forensics.image_channels import extract_gif_scanline_bits


def test_extract_gif_scanline_bits() -> None:
    # Build a minimal synthetic animated GIF where row 0 encodes 'FLAG{test}'
    msg = b"FLAG{test}"
    bits = "".join(f"{b:08b}" for b in msg)
    # Pad to 64 width
    w = max(64, len(bits))
    bits = bits.ljust(w, "0")

    im = Image.new("RGB", (w, 10), (0, 0, 0))
    for x, bit in enumerate(bits):
        color = (255, 255, 255) if bit == "1" else (0, 0, 0)
        im.putpixel((x, 0), color)

    buf = io.BytesIO()
    im.save(buf, format="GIF", save_all=True)
    buf.seek(0)

    recovered = extract_gif_scanline_bits(buf)
    assert any("FLAG{test}" in rec for rec in recovered)
