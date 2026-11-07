"""Forensics and reverse engineering helpers."""

from ctf_toolkit.forensics.audio_tools import (
    demodulate_audio_fsk,
    dtmf_digits_to_ascii,
    extract_audio_pcm_lsb,
    extract_audio_tone_bytes,
)
from ctf_toolkit.forensics.docx_tools import extract_docx_metadata
from ctf_toolkit.forensics.gzip_tools import extract_gzip_metadata
from ctf_toolkit.forensics.image_channels import (
    decode_qr_image,
    extract_alpha_direct_bytes,
    extract_channel_bytes,
    extract_channel_lsb,
    extract_gif_scanline_bits,
    extract_interleaved_lsb,
    extract_png_trailing_bytes,
    extract_sequential_rgb_bytes,
    find_flags_in_channel,
)
from ctf_toolkit.forensics.jpeg_tools import extract_jpeg_comments, repair_jpeg_header
from ctf_toolkit.forensics.pdf_tools import extract_pdf_metadata
from ctf_toolkit.forensics.png_tools import (
    extract_png_all_metadata,
    extract_png_text_chunks,
    extract_png_trailing_payload,
    repair_png_header,
)
from ctf_toolkit.forensics.pyc_decompile import decompile_pyc, extract_pyc_constants_raw
from ctf_toolkit.forensics.xlsx_tools import extract_xlsx_metadata
from ctf_toolkit.forensics.zip_recover import (
    assemble_sharded_zip,
    decompress_nested_stream,
    fast_zip_crypto_crack,
    recover_corrupted_zip,
    repair_zip_header,
)

__all__ = [
    "assemble_sharded_zip",
    "decompile_pyc",
    "decompress_nested_stream",
    "decode_qr_image",
    "demodulate_audio_fsk",
    "dtmf_digits_to_ascii",
    "extract_alpha_direct_bytes",
    "extract_audio_pcm_lsb",
    "extract_audio_tone_bytes",
    "extract_channel_bytes",
    "extract_channel_lsb",
    "extract_docx_metadata",
    "extract_gif_scanline_bits",
    "extract_gzip_metadata",
    "extract_interleaved_lsb",
    "extract_jpeg_comments",
    "extract_pdf_metadata",
    "extract_png_all_metadata",
    "extract_png_text_chunks",
    "extract_png_trailing_bytes",
    "extract_png_trailing_payload",
    "extract_pyc_constants_raw",
    "extract_sequential_rgb_bytes",
    "extract_xlsx_metadata",
    "fast_zip_crypto_crack",
    "find_flags_in_channel",
    "recover_corrupted_zip",
    "repair_jpeg_header",
    "repair_png_header",
    "repair_zip_header",
]
