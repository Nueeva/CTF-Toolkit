"""Oracle transports for interactive crypto attacks.

The attack primitives (`padding_oracle_decrypt_block` in
`lks_national_suite`, `ecb_byte_at_a_time_recover` in `block_attacks`)
accept plain callables, but nothing in the toolkit could produce those
callables from a real challenge service. This module is that missing
transport layer:

- Padding oracles:  ``Callable[[bytes], bool]``
- Query oracles:    ``Callable[[bytes], bytes]``  (ECB byte-at-a-time)

Transports: in-process function, TCP service, HTTP endpoint, subprocess.
Hex encoding is the default on the wire (the common CTF service shape);
pass ``encode``/``decode`` callables to override.
"""
from __future__ import annotations

import socket
import subprocess
import urllib.request
from typing import Callable

BoolOracle = Callable[[bytes], bool]
QueryOracle = Callable[[bytes], bytes]


def _hex_encode(data: bytes) -> bytes:
    return data.hex().encode()


def _hex_decode(data: bytes) -> bytes:
    return bytes.fromhex(data.decode().strip())


# ---------------------------------------------------------------------------
# Generic transports
# ---------------------------------------------------------------------------

def tcp_query_oracle(
    host: str,
    port: int,
    *,
    encode: Callable[[bytes], bytes] = _hex_encode,
    decode: Callable[[bytes], bytes] = _hex_decode,
    suffix: bytes = b"\n",
    timeout: float = 10.0,
    recv_size: int = 65536,
) -> QueryOracle:
    """Query oracle over a fresh TCP connection per query.

    Sends ``encode(payload) + suffix``, reads until EOF/timeout, returns
    ``decode(response)``.
    """

    def query(payload: bytes) -> bytes:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(encode(payload) + suffix)
            chunks: list[bytes] = []
            while True:
                try:
                    chunk = sock.recv(recv_size)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
        return decode(b"".join(chunks))

    return query


def tcp_padding_oracle(
    host: str,
    port: int,
    response_check: Callable[[bytes], bool],
    *,
    encode: Callable[[bytes], bytes] = _hex_encode,
    suffix: bytes = b"\n",
    timeout: float = 10.0,
) -> BoolOracle:
    """Padding oracle over TCP: True when `response_check(response)` holds."""

    def raw_query(payload: bytes) -> bytes:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(encode(payload) + suffix)
            chunks: list[bytes] = []
            while True:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
        return b"".join(chunks)

    def oracle(iv_ct: bytes) -> bool:
        return response_check(raw_query(iv_ct))

    return oracle


def http_padding_oracle(
    url: str,
    response_check: Callable[[bytes], bool],
    *,
    field: str = "ct",
    encoding: str = "hex",
    timeout: float = 10.0,
) -> BoolOracle:
    """Padding oracle over HTTP POST form data (`field` = hex/base64 of iv||ct)."""
    import base64 as _b64
    import urllib.parse as _up

    def oracle(iv_ct: bytes) -> bool:
        value = iv_ct.hex() if encoding == "hex" else _b64.b64encode(iv_ct).decode()
        body = _up.urlencode({field: value}).encode()
        req = urllib.request.Request(url, data=body, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return response_check(resp.read())
        except urllib.error.HTTPError as exc:  # an error status can be the signal
            return response_check(exc.read())

    return oracle


def subprocess_query_oracle(
    argv: list[str],
    *,
    decode: Callable[[bytes], bytes] = _hex_decode,
    timeout: float = 15.0,
) -> QueryOracle:
    """Query oracle running a local program per query.

    The placeholder ``{hex}`` in any argv element is replaced with the hex
    of the payload; without a placeholder the hex line is fed on stdin.
    """

    def query(payload: bytes) -> bytes:
        hexed = payload.hex()
        args = [a.replace("{hex}", hexed) for a in argv]
        stdin_data = None if any("{hex}" in a for a in argv) else (hexed + "\n").encode()
        proc = subprocess.run(
            args, input=stdin_data, capture_output=True, timeout=timeout
        )
        return decode(proc.stdout)

    return query


# ---------------------------------------------------------------------------
# Full-message attacks on top of the transports
# ---------------------------------------------------------------------------

def cbc_padding_oracle_decrypt(
    iv_ct: bytes,
    oracle: BoolOracle,
    *,
    block_size: int = 16,
    unpad: bool = True,
) -> bytes:
    """Decrypt a full ``IV || C1 || C2 ...`` message via a padding oracle."""
    from ctf_toolkit.crypto.aes import pkcs7_unpad
    from ctf_toolkit.crypto.lks_national_suite import padding_oracle_decrypt_block

    if len(iv_ct) % block_size != 0 or len(iv_ct) < 2 * block_size:
        raise ValueError("iv_ct must be IV plus at least one full block")
    blocks = [iv_ct[i : i + block_size] for i in range(0, len(iv_ct), block_size)]
    plaintext = bytearray()
    for i in range(1, len(blocks)):
        plaintext += padding_oracle_decrypt_block(blocks[i - 1], blocks[i], oracle, block_size)
    data = bytes(plaintext)
    if unpad:
        try:
            data = pkcs7_unpad(data, block_size)
        except Exception:
            pass
    return data
