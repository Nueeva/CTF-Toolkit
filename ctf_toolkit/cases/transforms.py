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
    "hex_encode": "hex_encode",
    "hex_decode": "hex_decode",
    "unhex": "hex_decode",
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
            size = 4 * ((len(data) + 2) // 3) if operation == "b64e" else 2 * len(data)
            if size > MAX_ARTIFACT_BYTES:
                raise ValueError(f"{operation} output exceeds the artifact size limit")
            # The existing recipe engine handles both encoders and aliases.
            output = run_recipe(operation, data).encode("ascii")
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


def base64_input_range(data: bytes, start: int, stop: int) -> tuple[int, int]:
    """Return the source range covering the Base64 quanta for output [start, stop)."""
    if start < 0 or stop <= start:
        raise ValueError("Select a nonempty byte range")
    first_symbol = (start // 3) * 4
    last_symbol = ((stop + 2) // 3) * 4 - 1
    first_offset = None
    symbol = 0
    for offset, value in enumerate(data):
        if value in _ASCII_WHITESPACE:
            continue
        if symbol == first_symbol:
            first_offset = offset
        if symbol == last_symbol and first_offset is not None:
            return first_offset, offset + 1
        symbol += 1
    raise ValueError("Selected bytes are outside the Base64 output")
