from __future__ import annotations

import struct


def assemble_sharded_records_le(data: bytes, header: bytes = b"LREC!\x00") -> bytes:
    """
    Assemble ordered sharded binary records prefixed with uint16 LE indices.
    Format: [Header][Record 0: <H uint16 index, 1 byte char]...[Record N]
    """
    if data.startswith(header):
        payload = data[len(header) :]
    else:
        payload = data

    records: dict[int, bytes] = {}
    record_size = 3
    num_records = len(payload) // record_size

    for i in range(num_records):
        chunk = payload[i * record_size : (i + 1) * record_size]
        idx, char_byte = struct.unpack("<Hc", chunk)
        records[idx] = char_byte

    return b"".join(records[k] for k in sorted(records.keys()))
