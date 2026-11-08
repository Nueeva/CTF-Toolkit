import cv2
from PIL import Image

from ctf_toolkit.forensics.image_channels import decode_qr_image


def test_decode_qr_synthetic_and_rotated() -> None:
    enc = cv2.QRCodeEncoder_create()
    qr_matrix = enc.encode("GETSFLAG{qr_synthetic_test}")
    # Upscale so detector has sufficient resolution
    qr_large = cv2.resize(qr_matrix, (250, 250), interpolation=cv2.INTER_NEAREST)
    im = Image.fromarray(qr_large)

    # Test direct orientation
    res0 = decode_qr_image(im)
    assert "GETSFLAG{qr_synthetic_test}" in res0

    # Test 90-degree rotated orientation
    res90 = decode_qr_image(im.rotate(90))
    assert "GETSFLAG{qr_synthetic_test}" in res90


def test_decode_qr_invalid_image() -> None:
    # Blank white image without QR code
    blank = Image.new("RGB", (100, 100), (255, 255, 255))
    res = decode_qr_image(blank)
    assert res == []
