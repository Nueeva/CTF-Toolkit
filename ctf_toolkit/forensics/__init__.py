"""Forensics and reverse engineering helpers."""

from ctf_toolkit.forensics.docx_tools import extract_docx_metadata
from ctf_toolkit.forensics.gzip_tools import extract_gzip_metadata
from ctf_toolkit.forensics.image_channels import (
    decode_qr_image,
    extract_gif_scanline_bits,
    extract_channel_bytes,
    extract_png_trailing_bytes,
    extract_sequential_rgb_bytes,
    find_flags_in_channel,
)
from ctf_toolkit.forensics.pdf_tools import extract_pdf_metadata
from ctf_toolkit.forensics.pyc_decompile import decompile_pyc, extract_pyc_constants_raw
from ctf_toolkit.forensics.xlsx_tools import extract_xlsx_metadata

__all__ = [
    "decode_qr_image",
    "extract_gif_scanline_bits",
    "decompile_pyc",
    "extract_channel_bytes",
    "extract_docx_metadata",
    "extract_gzip_metadata",
    "extract_pdf_metadata",
    "extract_png_trailing_bytes",
    "extract_pyc_constants_raw",
    "extract_sequential_rgb_bytes",
    "extract_xlsx_metadata",
    "find_flags_in_channel",
]
