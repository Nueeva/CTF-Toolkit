from __future__ import annotations

import io
import zipfile
import urllib.parse
from ctf_toolkit.pipeline import run_recipe
from ctf_toolkit.triage import triage_data
from ctf_toolkit.crypto.classical import repeating_key_xor
from ctf_toolkit.crypto.encoding import decode_html_entities
from ctf_toolkit.osint_misc.stego import encode_zero_width, decode_zero_width
from ctf_toolkit.reversing.transforms import endian_swap, byte_shift, xor_bytes


def test_synthetic_twin_crypto_multistage() -> None:
    """Benchmark: Multi-stage classical & stream cipher decoding."""
    flag = b"CTF{synthetic_multistage_crypto_twin_benchmark}"
    xor_key = b"TWINKEY"
    xored = repeating_key_xor(flag, xor_key)

    # Encode with base64 then hex
    import base64
    b64_stage = base64.b64encode(xored).decode()
    hex_stage = b64_stage.encode().hex()

    # Recipe pipeline execution
    pipeline = "hex_decode | b64d | xor:TWINKEY | flag_scan"
    recovered = run_recipe(pipeline, hex_stage)
    assert recovered == flag.decode()


def test_synthetic_twin_stego_zerowidth_triage() -> None:
    """Benchmark: Triage detects zero-width stego, extractor extracts payload."""
    carrier = "The CTF challenge looks like an ordinary text description. "
    hidden_flag = b"CTF{synthetic_zerowidth_stego_twin}"
    stego_payload = encode_zero_width(hidden_flag)
    stego_text = carrier + stego_payload

    # 1. Triage fingerprinter
    report = triage_data(stego_text.encode("utf-8"), target_label="stego_doc")
    assert "Zero-Width Steganography" in report.encodings_detected

    # 2. Stego extraction
    extracted = decode_zero_width(stego_text)
    assert extracted == hidden_flag


def test_synthetic_twin_forensics_polyglot_carving() -> None:
    """Benchmark: Polyglot image with appended ZIP archive."""
    png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 20

    # Create in-memory zip
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("secret.txt", "FLAG{synthetic_polyglot_zip_carved}")
    zip_bytes = zip_buf.getvalue()

    polyglot = png_header + zip_bytes

    # Triage analysis
    report = triage_data(polyglot, target_label="suspicious.png")
    assert report.magic_type == "PNG Image"
    assert any("ZIP" in s for s in report.suggestions)

    # Extraction test
    zip_idx = polyglot.find(b"PK\x03\x04")
    extracted_zip = polyglot[zip_idx:]
    with zipfile.ZipFile(io.BytesIO(extracted_zip)) as zf:
        content = zf.read("secret.txt").decode()
    assert content == "FLAG{synthetic_polyglot_zip_carved}"


def test_synthetic_twin_reversing_transforms() -> None:
    """Benchmark: Multi-layer binary reversing transformations."""
    flag = b"CTF{synthetic_reversing_transformation_twin}"
    # Transform: XOR 0x7A -> byte shift +3 -> endian swap (4-byte chunks)
    stage1 = bytes(b ^ 0x7A for b in flag)
    # Pad to 4-byte multiple
    pad_len = (4 - len(stage1) % 4) % 4
    stage1_padded = stage1 + b"\x00" * pad_len
    stage2 = byte_shift(stage1_padded, 3)
    stage3 = endian_swap(stage2, 4)

    # Invert transformations
    inv1 = endian_swap(stage3, 4)
    inv2 = byte_shift(inv1, -3)
    inv3 = bytes(b ^ 0x7A for b in inv2)
    recovered = inv3[:len(flag)]
    assert recovered == flag


def test_synthetic_twin_web_encoding_pipeline() -> None:
    """Benchmark: Nested multi-layer web encodings."""
    flag = "GETSFLAG{synthetic_nested_web_encodings_twin}"
    # Nested: HTML entities inside URL encoding
    html_enc = "&#71;&#69;&#84;&#83;&#70;&#76;&#65;&#71;&#123;synthetic_nested_web_encodings_twin&#125;"
    url_enc = urllib.parse.quote(html_enc)

    # Solve
    step1 = urllib.parse.unquote(url_enc)
    step2 = decode_html_entities(step1)
    assert step2 == flag
