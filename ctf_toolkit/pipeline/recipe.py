from __future__ import annotations

import base64
import html
import re
import unicodedata
from typing import Callable, Any

from ctf_toolkit.crypto.classical import (
    atbash,
    caesar_decrypt,
    rot_n,
    gray_decode_bytes,
    repeating_key_xor,
    beaufort_decrypt,
    autokey_decrypt,
)
from ctf_toolkit.crypto.encoding import (
    decode_html_entities,
    rle_decode,
    normalize_fullwidth,
    rot47,
)
from ctf_toolkit.crypto.rc4 import rc4_crypt
from ctf_toolkit.osint_misc.stego import decode_zero_width, decode_trailing_whitespace
from ctf_toolkit.osint_misc.rpn import eval_rpn, eval_rpn_tape


# Registry of pipeline operations: name -> callable(data, *args)
RECIPE_REGISTRY: dict[str, Callable[..., Any]] = {}


def register_op(name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        RECIPE_REGISTRY[name.lower()] = fn
        return fn
    return decorator


@register_op("b64d")
@register_op("base64_decode")
def op_b64d(data: Any, *args: str) -> bytes:
    if isinstance(data, bytes):
        raw = data.strip()
    else:
        raw = str(data).strip().encode()
    # Auto-pad
    padding = (4 - len(raw) % 4) % 4
    raw += b"=" * padding
    return base64.b64decode(raw)


@register_op("b64e")
@register_op("base64_encode")
def op_b64e(data: Any, *args: str) -> str:
    if isinstance(data, str):
        raw = data.encode()
    else:
        raw = bytes(data)
    return base64.b64encode(raw).decode()


@register_op("hex_decode")
@register_op("unhex")
def op_hex_decode(data: Any, *args: str) -> bytes:
    clean = (data.decode() if isinstance(data, bytes) else str(data)).strip().replace(" ", "").replace("\n", "")
    if len(clean) % 2 != 0:
        clean = "0" + clean
    return bytes.fromhex(clean)


@register_op("hex_encode")
def op_hex_encode(data: Any, *args: str) -> str:
    raw = data.encode() if isinstance(data, str) else bytes(data)
    return raw.hex()


@register_op("a85d")
@register_op("ascii85_decode")
def op_a85d(data: Any, *args: str) -> bytes:
    raw = (data if isinstance(data, bytes) else str(data).encode()).strip()
    return base64.a85decode(raw)


@register_op("b85d")
@register_op("base85_decode")
def op_b85d(data: Any, *args: str) -> bytes:
    raw = (data if isinstance(data, bytes) else str(data).encode()).strip()
    return base64.b85decode(raw)


@register_op("rot13")
def op_rot13(data: Any, *args: str) -> str:
    text = data.decode(errors="ignore") if isinstance(data, bytes) else str(data)
    return rot_n(text, 13)


@register_op("rot47")
def op_rot47(data: Any, *args: str) -> str:
    text = data.decode(errors="ignore") if isinstance(data, bytes) else str(data)
    return rot47(text)


@register_op("atbash")
def op_atbash(data: Any, *args: str) -> str:
    text = data.decode(errors="ignore") if isinstance(data, bytes) else str(data)
    return atbash(text)


@register_op("reverse")
@register_op("rev")
def op_reverse(data: Any, *args: str) -> Any:
    if isinstance(data, bytes):
        return data[::-1]
    return str(data)[::-1]


@register_op("xor")
def op_xor(data: Any, key_arg: str = "0x5a") -> bytes:
    raw = data.encode() if isinstance(data, str) else bytes(data)
    key_arg = key_arg.strip()
    if key_arg.startswith("0x") or key_arg.startswith("0X"):
        k = int(key_arg, 16)
        return bytes(b ^ k for b in raw)
    elif key_arg.isdigit():
        k = int(key_arg)
        return bytes(b ^ k for b in raw)
    else:
        # text repeating key
        k_bytes = key_arg.encode()
        return repeating_key_xor(raw, k_bytes)


@register_op("rc4")
def op_rc4(data: Any, key_arg: str = "key") -> bytes:
    raw = data.encode() if isinstance(data, str) else bytes(data)
    return rc4_crypt(key_arg.encode(), raw)


@register_op("rle_decode")
def op_rle_decode(data: Any, *args: str) -> str:
    text = data.decode(errors="ignore") if isinstance(data, bytes) else str(data)
    return rle_decode(text)


@register_op("flag_scan")
@register_op("grep_flag")
def op_flag_scan(data: Any, pattern: str = r"(?:GETSFLAG|CT|FLAG)\{[^\}]+\}") -> str:
    text = data.decode("latin-1", errors="ignore") if isinstance(data, bytes) else str(data)
    m = re.findall(pattern, text)
    if m:
        return "\n".join(m)
    return text


class RecipePipeline:
    """CyberChef-style recipe chaining pipeline engine."""

    def __init__(self, recipe_str: str) -> None:
        self.recipe_str = recipe_str
        self.steps = self._parse_recipe(recipe_str)

    def _parse_recipe(self, recipe_str: str) -> list[tuple[str, list[str]]]:
        steps: list[tuple[str, list[str]]] = []
        tokens = [s.strip() for s in recipe_str.split("|") if s.strip()]
        for token in tokens:
            if ":" in token:
                name, arg_str = token.split(":", 1)
                args = [a.strip() for a in arg_str.split(",")]
                steps.append((name.strip().lower(), args))
            else:
                steps.append((token.lower(), []))
        return steps

    def execute(self, initial_data: Any) -> Any:
        current = initial_data
        for op_name, args in self.steps:
            if op_name not in RECIPE_REGISTRY:
                raise ValueError(f"Unknown recipe operation: '{op_name}'. Available: {list(RECIPE_REGISTRY.keys())}")
            fn = RECIPE_REGISTRY[op_name]
            current = fn(current, *args)
        return current


def run_recipe(recipe_str: str, data: Any) -> Any:
    pipeline = RecipePipeline(recipe_str)
    return pipeline.execute(data)
