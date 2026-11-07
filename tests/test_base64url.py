from ctf_toolkit.crypto.classical import base64url_decode


def test_base64url_decode():
    encoded = "dT1HRVRTRkxBR3ttY2FfYmFzZTY0dXJsfQ"
    decoded = base64url_decode(encoded)
    assert decoded == b"u=GETSFLAG{mca_base64url}"


def test_base64url_with_special_chars():
    # Base64 standard: + and / -> Base64URL: - and _
    # b"\xfb\xff\xfe" in standard is +//+
    # in URL-safe is -__-
    raw = b"\xfb\xff\xfe"
    encoded_url = "-__-"
    assert base64url_decode(encoded_url) == raw
