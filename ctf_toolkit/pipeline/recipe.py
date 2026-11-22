from __future__ import annotations

import base64
import bz2
import gzip
import html
import lzma
import quopri
import re
import unicodedata
import urllib.parse
import zlib
from typing import Callable, Any

from ctf_toolkit.crypto.classical import (
    atbash,
    caesar_decrypt,
    columnar_transposition_decrypt,
    rot_n,
    rot18,
    vigenere_decrypt,
    gray_decode_bytes,
    repeating_key_xor,
    beaufort_decrypt,
    autokey_decrypt,
    porta_decrypt,
    rail_fence_decrypt,
)
from ctf_toolkit.crypto.encoding import (
    ascii85_decode,
    ascii85_encode,
    base16_decode,
    base16_encode,
    base32_decode,
    base32_encode,
    base32hex_decode,
    base32hex_encode,
    base36_decode,
    base36_encode,
    base45_decode,
    base45_encode,
    base58_decode,
    base58_encode,
    base58_ripple_decode,
    base58_ripple_encode,
    base62_decode,
    base62_encode,
    base64url_decode,
    base64url_encode,
    base85_decode,
    base85_encode,
    base91_decode,
    base91_encode,
    base_n_decode,
    base_n_encode,
    decode_html_entities,
    rle_decode,
    normalize_fullwidth,
    rot47,
    xxdecode,
    z85_decode,
    z85_encode,
)
from ctf_toolkit.crypto.rc4 import rc4_crypt
from ctf_toolkit.osint_misc.stego import decode_zero_width, decode_trailing_whitespace
from ctf_toolkit.osint_misc.rpn import eval_rpn, eval_rpn_tape
from ctf_toolkit.osint_misc.uudecode import decode_uu


# Registry of pipeline operations: name -> callable(data, *args)
RECIPE_REGISTRY: dict[str, Callable[..., Any]] = {}


def register_op(name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        RECIPE_REGISTRY[name.lower()] = fn
        return fn
    return decorator


def _as_bytes(data: Any) -> bytes:
    return data if isinstance(data, bytes) else str(data).encode("utf-8")


def _as_str(data: Any) -> str:
    return data.decode("utf-8", errors="ignore") if isinstance(data, bytes) else str(data)


@register_op("b64d")
@register_op("base64_decode")
def op_b64d(data: Any, *args: str) -> bytes:
    if isinstance(data, bytes):
        raw = re.sub(rb"\s+", b"", data)
    else:
        raw = re.sub(rb"\s+", b"", str(data).encode())
    padding = (4 - len(raw) % 4) % 4
    raw += b"=" * padding
    return base64.b64decode(raw)


@register_op("b64e")
@register_op("base64_encode")
def op_b64e(data: Any, *args: str) -> str:
    return base64.b64encode(_as_bytes(data)).decode()


@register_op("b64url_d")
@register_op("base64url_decode")
def op_b64url_d(data: Any, *args: str) -> bytes:
    return base64url_decode(data)


@register_op("b64url_e")
@register_op("base64url_encode")
def op_b64url_e(data: Any, *args: str) -> str:
    return base64url_encode(_as_bytes(data))


@register_op("b16d")
@register_op("hex_d")
@register_op("hex_decode")
@register_op("unhex")
def op_hex_decode(data: Any, *args: str) -> bytes:
    return base16_decode(data)


@register_op("b16e")
@register_op("hex_e")
@register_op("hex_encode")
def op_hex_encode(data: Any, *args: str) -> str:
    return base16_encode(_as_bytes(data))


@register_op("b32d")
@register_op("base32_decode")
def op_b32d(data: Any, *args: str) -> bytes:
    return base32_decode(data)


@register_op("b32e")
@register_op("base32_encode")
def op_b32e(data: Any, *args: str) -> str:
    return base32_encode(_as_bytes(data))


@register_op("b32hex")
@register_op("b32hex_d")
@register_op("base32hex")
@register_op("base32hex_decode")
def op_base32hex(data: Any, *args: str) -> bytes:
    return base32hex_decode(_as_str(data).strip())


@register_op("b32hex_e")
@register_op("base32hex_encode")
def op_base32hex_encode(data: Any, *args: str) -> str:
    return base32hex_encode(_as_bytes(data))


@register_op("b36d")
@register_op("base36_decode")
def op_b36d(data: Any, *args: str) -> bytes:
    return base36_decode(data)


@register_op("b36e")
@register_op("base36_encode")
def op_b36e(data: Any, *args: str) -> str:
    return base36_encode(_as_bytes(data))


@register_op("b45d")
@register_op("base45_decode")
def op_b45d(data: Any, *args: str) -> bytes:
    return base45_decode(_as_str(data).strip())


@register_op("b45e")
@register_op("base45_encode")
def op_b45e(data: Any, *args: str) -> str:
    return base45_encode(_as_bytes(data))


@register_op("b58d")
@register_op("base58_decode")
def op_b58d(data: Any, *args: str) -> bytes:
    return base58_decode(_as_str(data).strip())


@register_op("b58e")
@register_op("base58_encode")
def op_b58e(data: Any, *args: str) -> str:
    return base58_encode(_as_bytes(data))


@register_op("b58_ripple_d")
@register_op("base58_ripple_decode")
def op_b58_ripple_d(data: Any, *args: str) -> bytes:
    return base58_ripple_decode(_as_str(data).strip())


@register_op("b58_ripple_e")
@register_op("base58_ripple_encode")
def op_b58_ripple_e(data: Any, *args: str) -> str:
    return base58_ripple_encode(_as_bytes(data))


@register_op("b62d")
@register_op("base62_decode")
def op_b62d(data: Any, *args: str) -> bytes:
    return base62_decode(_as_str(data).strip())


@register_op("b62e")
@register_op("base62_encode")
def op_b62e(data: Any, *args: str) -> str:
    return base62_encode(_as_bytes(data))


@register_op("a85d")
@register_op("ascii85_decode")
def op_a85d(data: Any, *args: str) -> bytes:
    return ascii85_decode(data)


@register_op("a85e")
@register_op("ascii85_encode")
def op_a85e(data: Any, *args: str) -> str:
    return ascii85_encode(_as_bytes(data))


@register_op("b85d")
@register_op("base85_decode")
def op_b85d(data: Any, *args: str) -> bytes:
    return base85_decode(data)


@register_op("b85e")
@register_op("base85_encode")
def op_b85e(data: Any, *args: str) -> str:
    return base85_encode(_as_bytes(data))


@register_op("z85d")
@register_op("z85_decode")
def op_z85d(data: Any, *args: str) -> bytes:
    return z85_decode(_as_str(data).strip())


@register_op("z85e")
@register_op("z85_encode")
def op_z85e(data: Any, *args: str) -> str:
    return z85_encode(_as_bytes(data))


@register_op("b91d")
@register_op("base91_decode")
def op_base91_decode(data: Any, *args: str) -> bytes:
    return base91_decode(_as_str(data).strip())


@register_op("b91e")
@register_op("base91_encode")
def op_base91_encode(data: Any, *args: str) -> str:
    return base91_encode(_as_bytes(data))


@register_op("base_n_d")
@register_op("base_n_decode")
def op_base_n_d(data: Any, base_arg: str = "16") -> bytes:
    return base_n_decode(_as_str(data).strip(), int(base_arg))


@register_op("base_n_e")
@register_op("base_n_encode")
def op_base_n_e(data: Any, base_arg: str = "16") -> str:
    return base_n_encode(_as_bytes(data), int(base_arg))


@register_op("url_d")
@register_op("url_decode")
def op_url_d(data: Any, *args: str) -> str:
    return urllib.parse.unquote(_as_str(data))


@register_op("url_e")
@register_op("url_encode")
def op_url_e(data: Any, *args: str) -> str:
    return urllib.parse.quote(_as_str(data), safe="")


@register_op("qp_d")
@register_op("quoted_printable_decode")
def op_qp_d(data: Any, *args: str) -> bytes:
    return quopri.decodestring(_as_bytes(data))


@register_op("qp_e")
@register_op("quoted_printable_encode")
def op_qp_e(data: Any, *args: str) -> str:
    return quopri.encodestring(_as_bytes(data)).decode("ascii")


@register_op("html_d")
@register_op("html_decode")
def op_html_d(data: Any, *args: str) -> str:
    return decode_html_entities(_as_str(data))


@register_op("html_e")
@register_op("html_encode")
def op_html_e(data: Any, *args: str) -> str:
    return html.escape(_as_str(data))


@register_op("uu_d")
@register_op("uudecode")
def op_uu_d(data: Any, *args: str) -> bytes:
    return decode_uu(_as_str(data))


@register_op("xx_d")
@register_op("xxdecode")
def op_xx_d(data: Any, *args: str) -> bytes:
    return xxdecode(_as_str(data))


@register_op("rot13")
def op_rot13(data: Any, *args: str) -> str:
    return rot_n(_as_str(data), 13)


@register_op("rot47")
def op_rot47(data: Any, *args: str) -> str:
    return rot47(_as_str(data))


@register_op("rot18")
def op_rot18(data: Any, *args: str) -> str:
    return rot18(_as_str(data))


@register_op("caesar")
def op_caesar(data: Any, shift_arg: str = "13") -> str:
    return caesar_decrypt(_as_str(data), int(shift_arg))


@register_op("vigenere_d")
@register_op("vigenere")
def op_vigenere_d(data: Any, key_arg: str = "KEY") -> str:
    return vigenere_decrypt(_as_str(data), key_arg)


@register_op("columnar_d")
@register_op("columnar")
def op_columnar_d(data: Any, key_arg: str = "KEY") -> str:
    return columnar_transposition_decrypt(_as_str(data), key_arg)


@register_op("atbash")
def op_atbash(data: Any, *args: str) -> str:
    return atbash(_as_str(data))


@register_op("reverse")
@register_op("rev")
def op_reverse(data: Any, *args: str) -> Any:
    if isinstance(data, bytes):
        return data[::-1]
    return str(data)[::-1]


@register_op("xor")
def op_xor(data: Any, key_arg: str = "0x5a") -> bytes:
    raw = _as_bytes(data)
    key_arg = key_arg.strip()
    if key_arg.startswith("0x") or key_arg.startswith("0X"):
        k = int(key_arg, 16)
        return bytes(b ^ k for b in raw)
    elif key_arg.isdigit():
        k = int(key_arg)
        return bytes(b ^ k for b in raw)
    else:
        return repeating_key_xor(raw, key_arg.encode())


@register_op("rc4")
def op_rc4(data: Any, key_arg: str = "key") -> bytes:
    return rc4_crypt(key_arg.encode(), _as_bytes(data))


@register_op("rle_d")
@register_op("rle_decode")
def op_rle_decode(data: Any, *args: str) -> str:
    return rle_decode(_as_str(data))


@register_op("byte_shift")
def op_byte_shift(data: Any, shift_arg: str = "1") -> bytes:
    shift = int(shift_arg)
    return bytes((b + shift) & 0xFF for b in _as_bytes(data))


@register_op("zlib_d")
def op_zlib_d(data: Any, *args: str) -> bytes:
    return zlib.decompress(_as_bytes(data))


@register_op("gzip_d")
def op_gzip_d(data: Any, *args: str) -> bytes:
    return gzip.decompress(_as_bytes(data))


@register_op("bz2_d")
def op_bz2_d(data: Any, *args: str) -> bytes:
    return bz2.decompress(_as_bytes(data))


@register_op("lzma_d")
def op_lzma_d(data: Any, *args: str) -> bytes:
    return lzma.decompress(_as_bytes(data))


@register_op("flag_scan")
@register_op("grep_flag")
def op_flag_scan(data: Any, pattern: str = "") -> str:
    text = data.decode("latin-1", errors="ignore") if isinstance(data, bytes) else str(data)
    if pattern:
        m = re.findall(pattern, text, re.IGNORECASE)
        if m:
            return "\n".join(m)
    from ctf_toolkit.utils.flag_manager import get_flag_manager
    matches = get_flag_manager().extract_flags(text)
    if matches:
        return "\n".join(item["flag"] for item in matches)
    default_pat = r"(?:TECHCOMFEST\d*|COMPFEST\d*|GEMASTIK\d*|WRECKIT\d*|HOLOGY\d*|SLASHROOT\d*|GETSFLAG|CTFLEARN|picoCTF|SEKAI|HIDC\d*|ARA\d*|CHTB|HTB|THM|ASIS|DICE|HOPE|OOO|ARKAV|LACTF|ACTF|LKS|CTF|FLAG|CT)\{[^\}]+\}"
    m = re.findall(default_pat, text, re.IGNORECASE)
    if m:
        return "\n".join(m)
    return text


@register_op("porta")
@register_op("porta_d")
def op_porta(data: Any, key_arg: str = "KEY") -> str:
    return porta_decrypt(_as_str(data), key_arg)


@register_op("rail_fence")
@register_op("rail_fence_d")
def op_rail_fence(data: Any, rails_arg: str = "4") -> str:
    r = int(rails_arg) if rails_arg.isdigit() else 4
    return rail_fence_decrypt(_as_str(data), r)


@register_op("nibble_swap")
@register_op("swap_nibbles")
def op_nibble_swap(data: Any, *args: str) -> bytes:
    from ctf_toolkit.crypto.classical import nibble_swap
    return nibble_swap(_as_bytes(data))


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
