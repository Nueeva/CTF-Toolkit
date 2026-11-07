import gzip
import zlib
from ctf_toolkit.osint_misc.compression import decompress_blob


def test_decompress_blob_zlib():
    raw = b"Secret data inside zlib"
    compressed = zlib.compress(raw)
    fmt, decomp = decompress_blob(compressed)
    assert fmt == "zlib"
    assert decomp == raw


def test_decompress_blob_gzip():
    raw = b"Secret data inside gzip"
    compressed = gzip.compress(raw)
    fmt, decomp = decompress_blob(compressed)
    assert fmt == "gzip"
    assert decomp == raw
