from __future__ import annotations

import io
import plistlib
import struct
import tarfile
import zlib
from typing import Any


def decode_msgpack_raw(data: bytes) -> Any:
    """Pure-Python lightweight MessagePack wire format decoder."""
    idx = 0

    def _read(n: int) -> bytes:
        nonlocal idx
        chunk = data[idx : idx + n]
        idx += n
        return chunk

    def _parse() -> Any:
        nonlocal idx
        if idx >= len(data):
            return None
        b = data[idx]
        idx += 1
        if b <= 0x7F:
            return b
        if 0x80 <= b <= 0x8F:
            count = b & 0x0F
            return {_parse(): _parse() for _ in range(count)}
        if 0x90 <= b <= 0x9F:
            count = b & 0x0F
            return [_parse() for _ in range(count)]
        if 0xA0 <= b <= 0xBF:
            length = b & 0x1F
            return _read(length).decode("utf-8", errors="replace")
        if b == 0xC0:
            return None
        if b == 0xC2:
            return False
        if b == 0xC3:
            return True
        if b == 0xC4:
            length = _read(1)[0]
            return _read(length)
        if b == 0xCC:
            return _read(1)[0]
        if b == 0xCD:
            return int.from_bytes(_read(2), "big")
        if b == 0xCE:
            return int.from_bytes(_read(4), "big")
        if b == 0xCF:
            return int.from_bytes(_read(8), "big")
        if b == 0xD9:
            length = _read(1)[0]
            return _read(length).decode("utf-8", errors="replace")
        if b == 0xDA:
            length = int.from_bytes(_read(2), "big")
            return _read(length).decode("utf-8", errors="replace")
        if b == 0xDB:
            length = int.from_bytes(_read(4), "big")
            return _read(length).decode("utf-8", errors="replace")
        if b == 0xDC:
            count = int.from_bytes(_read(2), "big")
            return [_parse() for _ in range(count)]
        if b == 0xDE:
            count = int.from_bytes(_read(2), "big")
            return {_parse(): _parse() for _ in range(count)}
        if b >= 0xE0:
            return b - 256
        return b

    return _parse()


def decode_cbor_raw(data: bytes) -> Any:
    """Pure-Python RFC 8949 CBOR item decoder."""
    idx = 0

    def _read_uint(ai: int) -> int:
        nonlocal idx
        if ai < 24:
            return ai
        if ai == 24:
            val = data[idx]
            idx += 1
            return val
        if ai == 25:
            val = int.from_bytes(data[idx : idx + 2], "big")
            idx += 2
            return val
        if ai == 26:
            val = int.from_bytes(data[idx : idx + 4], "big")
            idx += 4
            return val
        if ai == 27:
            val = int.from_bytes(data[idx : idx + 8], "big")
            idx += 8
            return val
        return 0

    def _parse() -> Any:
        nonlocal idx
        if idx >= len(data):
            return None
        ib = data[idx]
        idx += 1
        mt = ib >> 5
        ai = ib & 0x1F
        val = _read_uint(ai)
        if mt == 0:
            return val
        if mt == 1:
            return -1 - val
        if mt == 2:
            raw = data[idx : idx + val]
            idx += val
            return raw
        if mt == 3:
            raw = data[idx : idx + val]
            idx += val
            return raw.decode("utf-8", errors="replace")
        if mt == 4:
            return [_parse() for _ in range(val)]
        if mt == 5:
            return {_parse(): _parse() for _ in range(val)}
        if mt == 6:
            return _parse()
        if mt == 7:
            if ai == 20:
                return False
            if ai == 21:
                return True
            if ai == 22:
                return None
        return val

    return _parse()


def decode_protobuf_raw(data: bytes) -> dict[int, list[Any]]:
    """
    Schema-less Protobuf raw wire-format decoder (equivalent to `protoc --decode_raw`).
    Supports varint (wire type 0), 64-bit (1), length-delimited bytes/strings (2), and 32-bit (5).
    """
    idx = 0
    fields: dict[int, list[Any]] = {}

    def _read_varint() -> int:
        nonlocal idx
        shift = 0
        res = 0
        while idx < len(data):
            b = data[idx]
            idx += 1
            res |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        return res

    while idx < len(data):
        tag = _read_varint()
        if tag == 0:
            break
        field_num = tag >> 3
        wire_type = tag & 0x07

        if wire_type == 0:
            val: Any = _read_varint()
        elif wire_type == 1:
            val = int.from_bytes(data[idx : idx + 8], "little")
            idx += 8
        elif wire_type == 2:
            length = _read_varint()
            chunk = data[idx : idx + length]
            idx += length
            try:
                text = chunk.decode("utf-8")
                val = text if all(32 <= ord(c) <= 126 or c in "\r\n\t" for c in text) else chunk
            except Exception:
                val = chunk
        elif wire_type == 5:
            val = int.from_bytes(data[idx : idx + 4], "little")
            idx += 4
        else:
            break

        fields.setdefault(field_num, []).append(val)

    return fields


def parse_asn1_der_strings(data: bytes) -> list[bytes]:
    """Scan and extract OCTET STRING, UTF8String, PrintableString, and IA5String from ASN.1 DER/PEM blobs."""
    import base64
    import re

    raw = data
    if b"-----BEGIN" in raw:
        b64_body = b"".join(
            line.strip()
            for line in raw.splitlines()
            if not line.strip().startswith(b"-----")
        )
        try:
            raw = base64.b64decode(b64_body)
        except Exception:
            pass

    extracted: list[bytes] = []

    def _walk(buf: bytes) -> None:
        i = 0
        while i < len(buf) - 2:
            tag = buf[i]
            length_byte = buf[i + 1]
            hdr_len = 2
            if length_byte & 0x80:
                num_bytes = length_byte & 0x7F
                if num_bytes == 0 or i + 2 + num_bytes > len(buf):
                    i += 1
                    continue
                length = int.from_bytes(buf[i + 2 : i + 2 + num_bytes], "big")
                hdr_len = 2 + num_bytes
            else:
                length = length_byte

            if i + hdr_len + length > len(buf):
                i += 1
                continue

            content = buf[i + hdr_len : i + hdr_len + length]
            # Constructed SEQUENCE (0x30) or SET (0x31) or context-specific constructed (0xA0..0xBF)
            if tag in (0x30, 0x31) or (tag & 0x20):
                _walk(content)
            elif tag in (0x04, 0x0C, 0x13, 0x16, 0x1E):
                if content:
                    extracted.append(content)
                    if content.startswith(b"\x30"):
                        _walk(content)
            i += hdr_len + length

    _walk(raw)
    return extracted


def parse_bplist_strings(data: bytes) -> list[str]:
    """Extract all strings and values from an Apple binary plist (`bplist00`) or XML plist."""
    out: list[str] = []
    try:
        obj = plistlib.loads(data)

        def _collect(item: Any) -> None:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, bytes):
                out.append(item.decode("utf-8", errors="ignore"))
            elif isinstance(item, dict):
                for k, v in item.items():
                    _collect(k)
                    _collect(v)
            elif isinstance(item, (list, tuple)):
                for x in item:
                    _collect(x)

        _collect(obj)
    except Exception:
        pass
    return out


def decompress_git_loose_object(data: bytes) -> bytes:
    """Decompress a zlib-compressed Git loose object (`.git/objects/xx/yyyy...`) and strip its header."""
    raw = zlib.decompress(data)
    nul_idx = raw.find(b"\x00")
    return raw[nul_idx + 1 :] if nul_idx != -1 else raw


def decompress_zlib_with_dict(data: bytes, zdict: bytes) -> bytes:
    """Decompress a zlib stream that requires a preset dictionary (`zdict`)."""
    dobj = zlib.decompressobj(zdict=zdict)
    return dobj.decompress(data) + dobj.flush()


def extract_tar_pax_headers(tar_bytes: bytes) -> dict[str, str]:
    """Extract extended PAX headers (`pax_headers`) from a TAR archive."""
    headers: dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:*") as tf:
        for k, v in tf.pax_headers.items():
            headers[str(k)] = str(v)
        for member in tf.getmembers():
            for k, v in member.pax_headers.items():
                headers[f"{member.name}:{k}"] = str(v)
    return headers


def reassemble_seq_chunks(chunks: list[bytes | tuple[int, bytes]]) -> bytes:
    """
    Reassemble out-of-order chunks either passed as `(seq_num, payload)` tuples
    or raw bytes prefixed with `SEQ:<n>:` / 4-byte big-endian sequence numbers.
    """
    import re

    parsed: list[tuple[int, bytes]] = []
    for idx, item in enumerate(chunks):
        if isinstance(item, tuple):
            parsed.append((int(item[0]), bytes(item[1])))
        else:
            m = re.match(rb"^(?:SEQ|PART|CHUNK)[:=_ -]?(\d+)[:\n\r ]+(.*)$", item, re.DOTALL | re.IGNORECASE)
            if m:
                parsed.append((int(m.group(1)), m.group(2)))
            elif len(item) > 4:
                seq = int.from_bytes(item[:4], "big")
                parsed.append((seq, item[4:]))
            else:
                parsed.append((idx, item))
    parsed.sort(key=lambda x: x[0])
    return b"".join(p[1] for p in parsed)


def decode_timestamp_delta_channel(timestamps: list[int], base: int = 1700000000, step: int = 128) -> str:
    """Decode covert channel characters encoded in epoch timestamp deltas: `t_i - base - i * step`."""
    chars = []
    for i, t in enumerate(timestamps):
        val = (t - base - i * step) & 0xFF
        if 32 <= val <= 126:
            chars.append(chr(val))
    return "".join(chars)
