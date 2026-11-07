from __future__ import annotations

import re


def bdecode(data: bytes | str) -> object:
    """Decode a bencoded byte sequence into native Python types (int, bytes, list, dict)."""
    raw: bytes = data.encode("utf-8") if isinstance(data, str) else data
    pos = 0

    def decode_next() -> object:
        nonlocal pos
        if pos >= len(raw):
            raise ValueError("Unexpected end of bencoded buffer")

        ch = raw[pos : pos + 1]

        # Integer: i<digits>e
        if ch == b"i":
            pos += 1
            end = raw.find(b"e", pos)
            if end == -1:
                raise ValueError("Unterminated bencode integer")
            val = int(raw[pos:end])
            pos = end + 1
            return val

        # Dictionary: d...e
        if ch == b"d":
            pos += 1
            d: dict[str, object] = {}
            while pos < len(raw) and raw[pos : pos + 1] != b"e":
                key_obj = decode_next()
                key_str = key_obj.decode("utf-8", errors="replace") if isinstance(key_obj, bytes) else str(key_obj)
                val_obj = decode_next()
                d[key_str] = val_obj
            pos += 1  # consume 'e'
            return d

        # List: l...e
        if ch == b"l":
            pos += 1
            lst: list[object] = []
            while pos < len(raw) and raw[pos : pos + 1] != b"e":
                lst.append(decode_next())
            pos += 1  # consume 'e'
            return lst

        # Byte String: <len>:<bytes>
        if ch in b"0123456789":
            colon = raw.find(b":", pos)
            if colon == -1:
                raise ValueError("Malformed bencode string length prefix")
            length = int(raw[pos:colon])
            start = colon + 1
            end = start + length
            if end > len(raw):
                raise ValueError("Bencode string exceeds buffer length")
            pos = end
            return raw[start:end]

        raise ValueError(f"Invalid bencode token at byte offset {pos}: {ch!r}")

    return decode_next()


def parse_torrent(data: bytes) -> dict[str, object]:
    """Parse a .torrent file and extract high-level metadata (tracker, comment, files)."""
    decoded = bdecode(data)
    if not isinstance(decoded, dict):
        raise ValueError("Invalid torrent file structure: root is not a dictionary")

    info = decoded.get("info", {})
    if isinstance(info, dict):
        name = info.get("name", b"").decode("utf-8", errors="replace") if isinstance(info.get("name"), bytes) else str(info.get("name", ""))
        length = info.get("length", 0)
    else:
        name = ""
        length = 0

    comment = decoded.get("comment", b"")
    comment_str = comment.decode("utf-8", errors="replace") if isinstance(comment, bytes) else str(comment)

    announce = decoded.get("announce", b"")
    announce_str = announce.decode("utf-8", errors="replace") if isinstance(announce, bytes) else str(announce)

    created_by = decoded.get("created by", b"")
    created_by_str = created_by.decode("utf-8", errors="replace") if isinstance(created_by, bytes) else str(created_by)

    return {
        "announce": announce_str,
        "comment": comment_str,
        "created_by": created_by_str,
        "name": name,
        "length": length,
    }
