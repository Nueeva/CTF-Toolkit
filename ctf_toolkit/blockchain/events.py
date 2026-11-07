from __future__ import annotations

import re


def decode_event_log_data(data_hex: str) -> dict[str, object]:
    """Decode EVM event log data field into structured ABI words and extracted strings."""
    clean_hex = data_hex.strip()
    if clean_hex.startswith("0x") or clean_hex.startswith("0X"):
        clean_hex = clean_hex[2:]

    if len(clean_hex) % 64 != 0:
        padding_needed = 64 - (len(clean_hex) % 64)
        clean_hex = clean_hex + ("0" * padding_needed)

    words: list[str] = [clean_hex[i : i + 64] for i in range(0, len(clean_hex), 64)]
    extracted_strings: list[str] = []

    try:
        raw_bytes = bytes.fromhex(clean_hex)
        ascii_matches = re.findall(rb"[\x20-\x7e]{4,}", raw_bytes)
        extracted_strings = [m.decode("latin1", errors="ignore") for m in ascii_matches]
    except Exception:
        pass

    return {
        "word_count": len(words),
        "words": words,
        "extracted_strings": extracted_strings,
        "hex_length": len(clean_hex),
    }


def reassemble_indexed_event_chunks(events: list[dict], topic_index: int = 1) -> str:
    """Sort events by integer index in specified topic, extract data words, and reassemble string."""
    indexed_parts = []
    for ev in events:
        topics = ev.get("topics", [])
        if len(topics) > topic_index:
            try:
                idx = int(topics[topic_index], 16)
            except Exception:
                continue
            data_hex = ev.get("data", "")
            if data_hex.startswith("0x") or data_hex.startswith("0X"):
                data_hex = data_hex[2:]
            try:
                raw_data = bytes.fromhex(data_hex)
                # Check if it has ABI string encoding: offset (32), length (32), data
                if len(raw_data) >= 64:
                    first_val = int.from_bytes(raw_data[:32], "big")
                    if first_val == 32:  # dynamic string offset
                        str_len = int.from_bytes(raw_data[32:64], "big")
                        str_bytes = raw_data[64 : 64 + str_len]
                        indexed_parts.append((idx, str_bytes.decode("latin1", errors="ignore")))
                        continue
                # Fallback: clean trailing nulls from raw data
                clean_chunk = raw_data.rstrip(b"\x00").decode("latin1", errors="ignore")
                indexed_parts.append((idx, clean_chunk))
            except Exception:
                pass

    indexed_parts.sort(key=lambda x: x[0])
    return "".join(part for _, part in indexed_parts)


def match_indexed_topic_keccak(candidates: list[str], target_topic: str) -> str | None:
    """Match candidates against an indexed topic hex using Keccak-256."""
    target_clean = target_topic.lower().replace("0x", "")
    try:
        from Crypto.Hash import keccak
        for cand in candidates:
            k = keccak.new(digest_bits=256)
            k.update(cand.encode("utf-8"))
            if k.hexdigest().lower() == target_clean:
                return cand
    except ImportError:
        pass
    return None
