from __future__ import annotations

import socket
import sys
import threading

from Crypto.Cipher import AES

from ctf_toolkit.crypto.aes import aes_cbc_decrypt, aes_cbc_encrypt
from ctf_toolkit.crypto.block_attacks import ecb_byte_at_a_time_recover
from ctf_toolkit.crypto.oracle import (
    cbc_padding_oracle_decrypt,
    subprocess_query_oracle,
    tcp_padding_oracle,
)

_KEY = bytes(range(16))
_IV = bytes(range(16, 32))


def _padding_oracle_fn(iv_ct: bytes) -> bool:
    try:
        aes_cbc_decrypt(iv_ct[16:], _KEY, iv_ct[:16])
        return True
    except Exception:
        return False


def test_cbc_padding_oracle_decrypt_local() -> None:
    flag = b"CTF{padding_oracle_local}"  # 27 bytes -> 2 blocks
    ct = aes_cbc_encrypt(flag, _KEY, _IV)
    recovered = cbc_padding_oracle_decrypt(_IV + ct, _padding_oracle_fn)
    assert recovered == flag


def test_cbc_padding_oracle_decrypt_tcp() -> None:
    flag = b"CTF{tcp_ok!}"  # 12 bytes -> 1 block
    ct = aes_cbc_encrypt(flag, _KEY, _IV)
    message = _IV + ct

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(16)
    port = server.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except OSError:
                return
            with conn:
                data = b""
                while not data.endswith(b"\n"):
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                try:
                    iv_ct = bytes.fromhex(data.decode().strip())
                    ok = _padding_oracle_fn(iv_ct)
                except Exception:
                    ok = False
                conn.sendall(b"OK padding\n" if ok else b"BAD padding\n")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        oracle = tcp_padding_oracle(
            "127.0.0.1", port, lambda resp: b"OK" in resp, timeout=5.0
        )
        recovered = cbc_padding_oracle_decrypt(message, oracle)
        assert recovered == flag
    finally:
        stop.set()
        server.close()


def test_ecb_byte_at_a_time_via_subprocess_oracle() -> None:
    secret = b"ECB-d3ad"
    script = (
        "import sys\n"
        "from Crypto.Cipher import AES\n"
        "key = bytes(range(16))\n"
        "data = bytes.fromhex(sys.stdin.read().strip())\n"
        f"secret = {secret!r}\n"
        "blob = data + secret\n"
        "blob += bytes([16 - len(blob) % 16]) * (16 - len(blob) % 16)\n"
        "print(AES.new(key, AES.MODE_ECB).encrypt(blob).hex())\n"
    )
    oracle = subprocess_query_oracle([sys.executable, "-c", script])
    recovered = ecb_byte_at_a_time_recover(oracle, max_bytes=len(secret))
    assert recovered == secret
