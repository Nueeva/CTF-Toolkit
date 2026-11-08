"""Compatibility module for ctf_toolkit.forensics.pdf imports."""
from __future__ import annotations

from ctf_toolkit.forensics.pdf_tools import (
    extract_pdf_all_text_tokens,
    extract_pdf_decompressed_streams,
    extract_pdf_metadata,
    repair_pdf_broken_header,
    scan_pdf_raw_objects,
)

__all__ = [
    "extract_pdf_metadata",
    "extract_pdf_decompressed_streams",
    "extract_pdf_all_text_tokens",
    "repair_pdf_broken_header",
    "scan_pdf_raw_objects",
]
