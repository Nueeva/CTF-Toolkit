import base64
import bz2
import gzip
import io
import lzma
import struct
import tarfile
import zipfile
import zlib
import numpy as np
from PIL import Image

from ctf_toolkit.forensics.image_channels import (
    extract_alpha_direct_bytes,
    extract_channel_lsb,
    extract_interleaved_lsb,
    extract_png_trailing_bytes,
)
from ctf_toolkit.forensics.png_tools import (
    extract_png_all_metadata,
    extract_png_trailing_payload,
)
from ctf_toolkit.forensics.zip_recover import (
    assemble_sharded_zip,
    decompress_nested_stream,
    fast_zip_crypto_crack,
)

_crctable = list(map(zipfile._gen_crc, range(256)))


def _encrypt_zipcrypto(plaintext: bytes, pwd: bytes, crc: int) -> bytes:
    key0, key1, key2 = 305419896, 591751049, 878082192

    def update_keys(c):
        nonlocal key0, key1, key2
        key0 = (key0 >> 8) ^ _crctable[(key0 ^ c) & 0xFF]
        key1 = ((key1 + (key0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        key2 = (key2 >> 8) ^ _crctable[(key2 ^ (key1 >> 24)) & 0xFF]

    for p in pwd:
        update_keys(p)

    check_byte = (crc >> 24) & 0xFF
    header = b"\x00" * 11 + bytes([check_byte])
    raw = header + plaintext
    enc = bytearray()
    for c in raw:
        k = key2 | 2
        cipher_byte = c ^ (((k * (k ^ 1)) >> 8) & 0xFF)
        update_keys(c)
        enc.append(cipher_byte)
    return bytes(enc)


def _make_encrypted_zip(filename: str, data: bytes, pwd: bytes) -> bytes:
    fn_bytes = filename.encode()
    crc = zlib.crc32(data) & 0xFFFFFFFF
    enc_data = _encrypt_zipcrypto(data, pwd, crc)
    lh = (
        struct.pack(
            "<4sHHHHHIIIHH",
            b"PK\x03\x04",
            20,
            1,
            0,
            0,
            0,
            crc,
            len(enc_data),
            len(data),
            len(fn_bytes),
            0,
        )
        + fn_bytes
        + enc_data
    )
    cd = (
        struct.pack(
            "<4sHHHHHHIIIHHHHHII",
            b"PK\x01\x02",
            20,
            20,
            1,
            0,
            0,
            0,
            crc,
            len(enc_data),
            len(data),
            len(fn_bytes),
            0,
            0,
            0,
            0,
            0,
            0,
        )
        + fn_bytes
    )
    eocd = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, len(cd), len(lh), 0)
    return lh + cd + eocd


def _make_dummy_png(width=10, height=10, mode="RGB", color=(100, 150, 200)) -> bytes:
    im = Image.new(mode, (width, height), color)
    buf = io.BytesIO()
    im.save(buf, format="PNG")
    return buf.getvalue()


def test_twin_678_polyglot_png_zip():
    flag = b"FLAG{twin_polyglot_png_zip}"
    png_data = _make_dummy_png()
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr("pesan.txt", flag)
    polyglot = png_data + zip_buf.getvalue()

    trailing = extract_png_trailing_payload(polyglot)
    assert trailing.startswith(b"PK\x03\x04")
    with zipfile.ZipFile(io.BytesIO(trailing)) as zf:
        recovered = zf.read("pesan.txt")
    assert recovered == flag


def test_twin_679_nested_png_zip_tar():
    flag = b"FLAG{twin_nested_png_zip_tar}"
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tf:
        ti = tarfile.TarInfo("secret.txt")
        ti.size = len(flag)
        tf.addfile(ti, io.BytesIO(flag))
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr("archive.tar", tar_buf.getvalue())
    polyglot = _make_dummy_png() + zip_buf.getvalue()

    trailing = extract_png_trailing_bytes(polyglot)
    unpacked = decompress_nested_stream(trailing)
    assert unpacked == flag


def test_twin_680_ztxt_compressed():
    flag = b"FLAG{twin_ztxt_compressed}"
    png = bytearray(_make_dummy_png())
    iend_pos = png.find(b"IEND") - 4
    keyword = b"Comment\x00\x00"
    compressed = zlib.compress(flag)
    chunk_data = keyword + compressed
    chunk_crc = zlib.crc32(b"zTXt" + chunk_data) & 0xFFFFFFFF
    chunk = struct.pack(">I4s", len(chunk_data), b"zTXt") + chunk_data + struct.pack(">I", chunk_crc)
    png_with_ztxt = bytes(png[:iend_pos] + chunk + png[iend_pos:])

    meta = extract_png_all_metadata(png_with_ztxt)
    assert "Comment" in meta
    assert meta["Comment"] == flag


def test_twin_681_truncated_png_text():
    flag = b"FLAG{twin_truncated_recovery}"
    png = bytearray(_make_dummy_png())
    iend_pos = png.find(b"IEND") - 4
    chunk_data = b"Comment\x00" + flag
    chunk_crc = zlib.crc32(b"tEXt" + chunk_data) & 0xFFFFFFFF
    chunk = struct.pack(">I4s", len(chunk_data), b"tEXt") + chunk_data + struct.pack(">I", chunk_crc)
    crafted = bytes(png[:iend_pos] + chunk)

    meta = extract_png_all_metadata(crafted)
    assert meta.get("Comment") == flag


def test_twin_682_big_endian_binary():
    flag_str = "FLAG{twin_big_endian_pack}"
    encoded = flag_str.encode("utf-16-be")
    decoded = encoded.decode("utf-16-be")
    assert decoded == flag_str


def test_twin_683_zipcrypto_wordlist():
    flag = b"FLAG{twin_zipcrypto_wordlist}"
    zip_bytes = _make_encrypted_zip("flag.txt", flag, b"secretkey")

    res = fast_zip_crypto_crack(zip_bytes, [b"admin", b"123456", b"secretkey", b"guest"])
    assert res is not None
    pwd, data = res
    assert pwd == b"secretkey"
    assert data == flag


def test_twin_684_nested_zip_two_passwords():
    flag = b"FLAG{twin_nested_zip_passwords}"
    inner_zip = _make_encrypted_zip("flag.txt", flag, b"pass_inner")
    outer_zip = _make_encrypted_zip("dalam.zip", inner_zip, b"pass_outer")

    res1 = fast_zip_crypto_crack(outer_zip, [b"wrong", b"pass_outer"])
    assert res1 is not None
    _, inner_recovered = res1
    res2 = fast_zip_crypto_crack(inner_recovered, [b"wrong", b"pass_inner"])
    assert res2 is not None
    _, recovered_flag = res2
    assert recovered_flag == flag


def test_twin_685_nested_zip_double_password():
    flag = b"FLAG{twin_double_pw_zip}"
    inner_zip = _make_encrypted_zip("flag.txt", flag, b"penguin")
    outer_zip = _make_encrypted_zip("inner.zip", inner_zip, b"winter")

    r1 = fast_zip_crypto_crack(outer_zip, [b"winter", b"summer"])
    assert r1 is not None
    r2 = fast_zip_crypto_crack(r1[1], [b"penguin", b"polar"])
    assert r2 is not None
    assert r2[1] == flag


def test_twin_686_zip_in_zip_unencrypted():
    flag = b"FLAG{twin_matryoshka_uncompressed}"
    b3 = io.BytesIO()
    with zipfile.ZipFile(b3, "w") as z:
        z.writestr("flag.txt", flag)
    b2 = io.BytesIO()
    with zipfile.ZipFile(b2, "w") as z:
        z.writestr("level3.zip", b3.getvalue())
    b1 = io.BytesIO()
    with zipfile.ZipFile(b1, "w") as z:
        z.writestr("level2.zip", b2.getvalue())

    res = decompress_nested_stream(b1.getvalue())
    assert res == flag


def test_twin_687_multi_compress_chain():
    flag = b"FLAG{twin_gz_bz2_xz_tar}"
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tf:
        ti = tarfile.TarInfo("flag.txt")
        ti.size = len(flag)
        tf.addfile(ti, io.BytesIO(flag))
    data = tar_buf.getvalue()
    data = lzma.compress(data)
    data = bz2.compress(data)
    data = gzip.compress(data)

    recovered = decompress_nested_stream(data)
    assert recovered == flag


def test_twin_688_recursive_gzip():
    flag = b"FLAG{twin_recursive_gzip}"
    data = flag
    for _ in range(5):
        data = gzip.compress(data)
    recovered = decompress_nested_stream(data)
    assert recovered == flag


def test_twin_689_zip_containing_targz():
    flag = b"FLAG{twin_zip_of_targz}"
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w:gz") as tf:
        ti = tarfile.TarInfo("flag.txt")
        ti.size = len(flag)
        tf.addfile(ti, io.BytesIO(flag))
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr("package.tar.gz", tar_buf.getvalue())

    recovered = decompress_nested_stream(zip_buf.getvalue())
    assert recovered == flag


def test_twin_690_sharded_zip_assemble():
    flag = b"FLAG{twin_zip_many_shards}"
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        for i in range(len(flag)):
            zf.writestr(f"part_{i:03d}.dat", bytes([flag[i]]))

    combined = assemble_sharded_zip(zip_buf.getvalue())
    assert combined == flag


def test_twin_691_zip_header_comment():
    flag = b"FLAG{twin_comment_beats_pw}"
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr("dummy.txt", b"nothing here")
        zf.comment = b"flag: " + flag

    zf_read = zipfile.ZipFile(io.BytesIO(zip_buf.getvalue()))
    assert flag in zf_read.comment


def test_twin_692_image_channel_red_lsb():
    flag = b"FLAG{twin_img_red_lsb}"
    bits = np.unpackbits(np.frombuffer(flag, dtype=np.uint8))
    arr = np.zeros((10, len(bits) // 10 + 1, 3), dtype=np.uint8)
    flat_r = arr[..., 0].flatten()
    flat_r[: len(bits)] = bits
    arr[..., 0] = flat_r.reshape(arr[..., 0].shape)
    im = Image.fromarray(arr)
    buf = io.BytesIO()
    im.save(buf, format="PNG")

    extracted = extract_channel_lsb(buf.getvalue(), channel="R", bit_pos=0)
    assert extracted.startswith(flag)


def test_twin_693_image_channel_blue_lsb():
    flag = b"FLAG{twin_img_blue_lsb}"
    bits = np.unpackbits(np.frombuffer(flag, dtype=np.uint8))
    arr = np.zeros((10, len(bits) // 10 + 1, 3), dtype=np.uint8)
    flat_b = arr[..., 2].flatten()
    flat_b[: len(bits)] = bits
    arr[..., 2] = flat_b.reshape(arr[..., 2].shape)
    im = Image.fromarray(arr)
    buf = io.BytesIO()
    im.save(buf, format="PNG")

    extracted = extract_channel_lsb(buf.getvalue(), channel="B", bit_pos=0)
    assert extracted.startswith(flag)


def test_twin_694_image_interleaved_2bit_lsb():
    flag = b"FLAG{twin_img_two_bits}"
    vals = []
    for b in flag:
        vals.extend([(b >> 6) & 3, (b >> 4) & 3, (b >> 2) & 3, b & 3])
    arr = np.zeros((10, (len(vals) + 2) // 3 // 10 + 2, 3), dtype=np.uint8)
    flat = arr.flatten()
    flat[: len(vals)] = vals
    arr = flat.reshape(arr.shape)
    im = Image.fromarray(arr)
    buf = io.BytesIO()
    im.save(buf, format="PNG")

    extracted = extract_interleaved_lsb(buf.getvalue(), bit_depth=2, bit_order="big")
    assert extracted.startswith(flag)


def test_twin_695_image_interleaved_base64_lsb():
    flag = b"FLAG{twin_img_base64_lsb}"
    b64_payload = base64.b64encode(flag)
    bits = np.unpackbits(np.frombuffer(b64_payload, dtype=np.uint8))
    arr = np.zeros((10, (len(bits) + 2) // 3 // 10 + 2, 3), dtype=np.uint8)
    flat = arr.flatten()
    flat[: len(bits)] = bits
    arr = flat.reshape(arr.shape)
    im = Image.fromarray(arr)
    buf = io.BytesIO()
    im.save(buf, format="PNG")

    extracted = extract_interleaved_lsb(buf.getvalue(), bit_depth=1, bit_order="big")
    assert extracted.startswith(b64_payload)
    assert base64.b64decode(extracted[: len(b64_payload)]) == flag


def test_twin_696_image_interleaved_reversed_lsb():
    flag = b"FLAG{twin_reversed_lsb}"
    rev_flag = flag[::-1]
    bits = np.unpackbits(np.frombuffer(rev_flag, dtype=np.uint8))
    arr = np.zeros((10, (len(bits) + 2) // 3 // 10 + 2, 3), dtype=np.uint8)
    flat = arr.flatten()
    flat[: len(bits)] = bits
    arr = flat.reshape(arr.shape)
    im = Image.fromarray(arr)
    buf = io.BytesIO()
    im.save(buf, format="PNG")

    extracted = extract_interleaved_lsb(buf.getvalue(), bit_depth=1, bit_order="big")
    assert extracted.startswith(rev_flag)
    assert extracted[: len(flag)][::-1] == flag


def test_twin_697_image_trailing_zip():
    flag = b"FLAG{twin_png_trailing_zip}"
    png_data = _make_dummy_png()
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr("flag.txt", flag)
    polyglot = png_data + zip_buf.getvalue()

    trailing = extract_png_trailing_bytes(polyglot)
    with zipfile.ZipFile(io.BytesIO(trailing)) as zf:
        recovered = zf.read("flag.txt")
    assert recovered == flag


def test_twin_698_image_trailing_gzip():
    flag = b"FLAG{twin_png_trailing_gzip}"
    gz = gzip.compress(flag)
    polyglot = _make_dummy_png() + gz

    trailing = extract_png_trailing_bytes(polyglot)
    assert gzip.decompress(trailing) == flag


def test_twin_699_image_ztxt_metadata():
    flag = b"FLAG{twin_ztxt_metadata}"
    png = bytearray(_make_dummy_png())
    iend_pos = png.find(b"IEND") - 4
    chunk_data = b"Comment\x00\x00" + zlib.compress(flag)
    chunk_crc = zlib.crc32(b"zTXt" + chunk_data) & 0xFFFFFFFF
    chunk = struct.pack(">I4s", len(chunk_data), b"zTXt") + chunk_data + struct.pack(">I", chunk_crc)
    png_with_chunk = bytes(png[:iend_pos] + chunk + png[iend_pos:])

    meta = extract_png_all_metadata(png_with_chunk)
    assert meta.get("Comment") == flag


def test_twin_700_image_itxt_metadata():
    flag = b"FLAG{twin_itxt_metadata}"
    png = bytearray(_make_dummy_png())
    iend_pos = png.find(b"IEND") - 4
    chunk_data = b"Comment\x00\x01\x00\x00\x00" + zlib.compress(flag)
    chunk_crc = zlib.crc32(b"iTXt" + chunk_data) & 0xFFFFFFFF
    chunk = struct.pack(">I4s", len(chunk_data), b"iTXt") + chunk_data + struct.pack(">I", chunk_crc)
    png_with_chunk = bytes(png[:iend_pos] + chunk + png[iend_pos:])

    meta = extract_png_all_metadata(png_with_chunk)
    assert meta.get("Comment") == flag


def test_twin_701_image_alpha_channel_lsb():
    flag = b"FLAG{twin_alpha_lsb}"
    bits = np.unpackbits(np.frombuffer(flag, dtype=np.uint8))
    arr = np.zeros((10, len(bits) // 10 + 1, 4), dtype=np.uint8)
    flat_a = arr[..., 3].flatten()
    flat_a[: len(bits)] = bits
    arr[..., 3] = flat_a.reshape(arr[..., 3].shape)
    im = Image.fromarray(arr, mode="RGBA")
    buf = io.BytesIO()
    im.save(buf, format="PNG")

    extracted = extract_channel_lsb(buf.getvalue(), channel="A", bit_pos=0)
    assert extracted.startswith(flag)


def test_twin_702_image_alpha_direct_bytes():
    flag = b"FLAG{twin_alpha_direct_bytes}"
    arr = np.zeros((10, 50, 4), dtype=np.uint8)
    arr[0, : len(flag), 3] = list(flag)
    im = Image.fromarray(arr, mode="RGBA")
    buf = io.BytesIO()
    im.save(buf, format="PNG")

    raw_alpha = extract_alpha_direct_bytes(buf.getvalue())
    assert flag in raw_alpha
