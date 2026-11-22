"""Bounded, deterministic codecs shared by case review and recipe replay."""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass

from ctf_toolkit.pipeline import run_recipe

MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
MAX_DERIVED_BYTES = 128 * 1024 * 1024
MAX_CHILDREN = 256
MAX_DEPTH = 4
MAX_STEPS = 16
ENGINE_VERSION = "1"
_ASCII_WHITESPACE = b" \t\r\n\v\f"
_ALIASES = {
    "b64e": "b64e",
    "base64_encode": "b64e",
    "b64d": "b64d",
    "base64_decode": "b64d",
    "b64url_e": "b64url_e",
    "base64url_encode": "b64url_e",
    "b64url_d": "b64url_d",
    "base64url_decode": "b64url_d",
    "b16e": "hex_encode",
    "hex_e": "hex_encode",
    "hex_encode": "hex_encode",
    "b16d": "hex_decode",
    "hex_d": "hex_decode",
    "hex_decode": "hex_decode",
    "unhex": "hex_decode",
    "b32e": "b32e",
    "base32_encode": "b32e",
    "b32d": "b32d",
    "base32_decode": "b32d",
    "b32hex_e": "b32hex_e",
    "base32hex_encode": "b32hex_e",
    "b32hex_d": "b32hex_d",
    "b32hex": "b32hex_d",
    "base32hex": "b32hex_d",
    "base32hex_decode": "b32hex_d",
    "b36e": "b36e",
    "base36_encode": "b36e",
    "b36d": "b36d",
    "base36_decode": "b36d",
    "b45e": "b45e",
    "base45_encode": "b45e",
    "b45d": "b45d",
    "base45_decode": "b45d",
    "b58e": "b58e",
    "base58_encode": "b58e",
    "b58d": "b58d",
    "base58_decode": "b58d",
    "b58_ripple_e": "b58_ripple_e",
    "base58_ripple_encode": "b58_ripple_e",
    "b58_ripple_d": "b58_ripple_d",
    "base58_ripple_decode": "b58_ripple_d",
    "b62e": "b62e",
    "base62_encode": "b62e",
    "b62d": "b62d",
    "base62_decode": "b62d",
    "b85e": "b85e",
    "base85_encode": "b85e",
    "b85d": "b85d",
    "base85_decode": "b85d",
    "a85e": "a85e",
    "ascii85_encode": "a85e",
    "a85d": "a85d",
    "ascii85_decode": "a85d",
    "z85e": "z85e",
    "z85_encode": "z85e",
    "z85d": "z85d",
    "z85_decode": "z85d",
    "b91e": "b91e",
    "base91_encode": "b91e",
    "b91d": "b91d",
    "base91_decode": "b91d",
    "rot13": "rot13",
    "rot47": "rot47",
    "atbash": "atbash",
    "reverse": "reverse",
    "rev": "reverse",
    "url_d": "url_d",
    "url_decode": "url_d",
    "url_e": "url_e",
    "url_encode": "url_e",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compact_ascii(data: bytes) -> bytes:
    return data.translate(None, _ASCII_WHITESPACE)


def decode_base64(data: bytes) -> bytes:
    compact = compact_ascii(data)
    result = base64.b64decode(compact, validate=True)
    if base64.b64encode(result) != compact:
        raise ValueError("Base64 has noncanonical padding or trailing bits")
    return result


def decode_hex(data: bytes) -> bytes:
    return binascii.unhexlify(compact_ascii(data))


def encoding_candidates(data: bytes) -> list[str]:
    if not data.strip(_ASCII_WHITESPACE):
        return []
    options = []
    for name, decoder in (("base64", decode_base64), ("hex", decode_hex)):
        try:
            decoder(data)
        except ValueError:
            continue
        options.append(name)
    return options


def extended_encoding_candidates(data: bytes) -> list[str]:
    """Identify all plausible Base encoding candidates across Base16..Base91."""
    compact = compact_ascii(data)
    if not compact:
        return []
    options = list(encoding_candidates(data))
    text = compact.decode("ascii", errors="ignore")
    if len(text) != len(compact):
        return options
    from ctf_toolkit.crypto.encoding import (
        base32_decode_autopad,
        base32hex_decode,
        base36_decode,
        base45_decode,
        base58_decode,
        base62_decode,
        base64url_decode,
        base85_decode,
        z85_decode,
    )
    checks = [
        ("base64url", lambda s: base64url_decode(s) if ("-" in s or "_" in s) else (_ for _ in ()).throw(ValueError())),
        ("base32", lambda s: base32_decode_autopad(s) if len(s) >= 8 and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=" for c in s) else (_ for _ in ()).throw(ValueError())),
        ("base32hex", lambda s: base32hex_decode(s) if len(s) >= 8 and all(c in "0123456789ABCDEFGHIJKLMNOPQRSTUV=" for c in s) else (_ for _ in ()).throw(ValueError())),
        ("base45", lambda s: base45_decode(s) if len(s) >= 3 else (_ for _ in ()).throw(ValueError())),
        ("base58", lambda s: base58_decode(s) if len(s) >= 4 else (_ for _ in ()).throw(ValueError())),
        ("base62", lambda s: base62_decode(s) if len(s) >= 4 else (_ for _ in ()).throw(ValueError())),
        ("base36", lambda s: base36_decode(s) if len(s) >= 4 else (_ for _ in ()).throw(ValueError())),
        ("base85", lambda s: base85_decode(s) if len(s) >= 5 else (_ for _ in ()).throw(ValueError())),
        ("z85", lambda s: z85_decode(s) if len(s) >= 5 and len(s) % 5 == 0 else (_ for _ in ()).throw(ValueError())),
    ]
    for label, fn in checks:
        if label in options:
            continue
        try:
            out = fn(text)
            if out:
                options.append(label)
        except Exception:
            continue
    return options


def parse_recipe(recipe: str) -> list[str]:
    names = recipe.strip().split("|")
    if len(names) > MAX_STEPS:
        raise ValueError(f"A case recipe allows up to {MAX_STEPS} steps")
    steps = []
    for name in names:
        operation = _ALIASES.get(name.strip().lower())
        if operation is None:
            raise ValueError(f"Unsupported case recipe operation: {name.strip()!r}")
        steps.append(operation)
    return steps


@dataclass(frozen=True)
class TransformResult:
    operation: str
    output: bytes
    source: dict


def apply_recipe(
    data: bytes, recipe: str, *, materialize: bool = True
) -> list[TransformResult]:
    """Run a case recipe with a fixed limit on each result and all results combined."""
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("Recipe input exceeds the artifact size limit")
    results = []
    retained = 0
    for operation in parse_recipe(recipe):
        if operation == "b64d":
            output = decode_base64(data)
        elif operation == "hex_decode":
            output = decode_hex(data)
        else:
            res = run_recipe(operation, data)
            output = res if isinstance(res, bytes) else str(res).encode("utf-8")
            if len(output) > MAX_ARTIFACT_BYTES:
                raise ValueError(f"{operation} output exceeds the artifact size limit")
        retained += len(output)
        if retained > MAX_DERIVED_BYTES:
            raise ValueError("Recipe exceeds the total output size limit")
        location = {"kind": "codec", "input_size": len(data)}
        item = TransformResult(operation, output, location)
        if not materialize:
            results.clear()
        results.append(item)
        data = output
    return results


def _non_ws_offsets(data: bytes) -> list[int]:
    return [i for i, b in enumerate(data) if b not in _ASCII_WHITESPACE]


def base64_input_range(data: bytes, start: int, stop: int) -> tuple[int, int]:
    """Return the source range covering the Base64 quanta for output [start, stop)."""
    if start < 0 or stop <= start:
        raise ValueError("Select a nonempty byte range")
    first_symbol = (start // 3) * 4
    last_symbol = ((stop + 2) // 3) * 4 - 1
    offsets = _non_ws_offsets(data)
    if not offsets or first_symbol >= len(offsets) or last_symbol >= len(offsets):
        raise ValueError("Selected bytes are outside the Base64 output")
    return offsets[first_symbol], offsets[last_symbol] + 1


def codec_input_range(operation: str, data: bytes, start: int, stop: int) -> tuple[int, int]:
    """Return the source byte interval in `data` that produced output bytes [start, stop) under `operation`."""
    if start < 0 or stop <= start:
        raise ValueError("Select a nonempty byte range")
    if operation == "b64d":
        return base64_input_range(data, start, stop)

    offsets = _non_ws_offsets(data)
    if not offsets:
        raise ValueError(f"Selected bytes are outside the {operation} output")

    if operation == "b64url_d":
        first_sym = (start // 3) * 4
        last_sym = min(len(offsets) - 1, ((stop + 2) // 3) * 4 - 1)
        if first_sym >= len(offsets):
            raise ValueError("Selected bytes are outside the Base64URL output")
        return offsets[first_sym], offsets[last_sym] + 1

    if operation in ("b32d", "b32hex_d"):
        first_sym = (start // 5) * 8
        last_sym = min(len(offsets) - 1, ((stop + 4) // 5) * 8 - 1)
        if first_sym >= len(offsets):
            raise ValueError(f"Selected bytes are outside the {operation} output")
        return offsets[first_sym], offsets[last_sym] + 1

    if operation == "hex_decode":
        first_sym = start * 2
        last_sym = stop * 2 - 1
        if last_sym >= len(offsets):
            raise ValueError("Selected bytes are outside the Hex output")
        return offsets[first_sym], offsets[last_sym] + 1

    if operation == "b45d":
        first_sym = (start // 2) * 3
        last_sym = min(len(offsets) - 1, ((stop + 1) // 2) * 3 - 1)
        if first_sym >= len(offsets):
            raise ValueError("Selected bytes are outside the Base45 output")
        return offsets[first_sym], offsets[last_sym] + 1

    if operation in ("b85d", "z85d"):
        first_sym = (start // 4) * 5
        last_sym = min(len(offsets) - 1, ((stop + 3) // 4) * 5 - 1)
        if first_sym >= len(offsets):
            raise ValueError(f"Selected bytes are outside the {operation} output")
        return offsets[first_sym], offsets[last_sym] + 1

    if operation in ("rot13", "rot47", "atbash"):
        if stop > len(data):
            raise ValueError(f"Selected bytes are outside the {operation} output")
        return start, stop

    if operation == "reverse":
        if stop > len(data):
            raise ValueError("Selected bytes are outside the reversed output")
        return len(data) - stop, len(data) - start

    # Whole-integer radix and stream codecs (b36d, b58d, b58_ripple_d, b62d, a85d, b91d, etc.)
    return offsets[0], offsets[-1] + 1
