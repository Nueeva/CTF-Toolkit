import io
import gzip
from ctf_toolkit.forensics.gzip_tools import extract_gzip_metadata


def test_extract_gzip_metadata():
    buf = io.BytesIO()
    with gzip.GzipFile(filename="secret.txt", mode="wb", fileobj=buf, mtime=12345678) as gz:
        gz.write(b"Hello from inside gzip!")

    raw_gz = bytearray(buf.getvalue())
    # Manually append comment flag into gzip header:
    # Set FCOMMENT bit (0x10) in flag byte (offset 3)
    raw_gz[3] |= 0x10
    # Insert comment string after filename
    # Find null terminator of filename
    fn_end = raw_gz.find(b"\x00", 10)
    comment = b"GETSFLAG{test_gzip_comment}\x00"
    modified_gz = raw_gz[:fn_end+1] + comment + raw_gz[fn_end+1:]

    meta = extract_gzip_metadata(bytes(modified_gz))
    assert meta.get("filename") == "secret.txt"
    assert meta.get("comment") == "GETSFLAG{test_gzip_comment}"
    assert meta.get("mtime") == "12345678"
