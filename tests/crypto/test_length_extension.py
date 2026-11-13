"""Known-answer tests for the hash length extension module.

The "attacker" functions only ever receive the original digest and the total
length; the secret is used here (via hashlib) solely to compute ground truth.
"""

from __future__ import annotations

import hashlib

from ctf_toolkit.crypto.length_extension import (
    _md5_hash,
    _sha1_hash,
    _sha256_hash,
    glue_padding_md,
    glue_padding_sha,
    length_extend,
    md5_extend,
    sha1_extend,
    sha256_extend,
)

_EXTENDERS = {"md5": md5_extend, "sha1": sha1_extend, "sha256": sha256_extend}
_GLUES = {"md5": glue_padding_md, "sha1": glue_padding_sha, "sha256": glue_padding_sha}


def _check_extend(algo: str, secret: bytes, msg: bytes, append: bytes) -> None:
    orig = hashlib.new(algo, secret + msg).hexdigest()
    total = len(secret) + len(msg)
    new_digest, tail = _EXTENDERS[algo](orig, total, append)
    glue = _GLUES[algo](total)
    assert tail == glue + append
    expected = hashlib.new(algo, secret + msg + glue + append).hexdigest()
    assert new_digest == expected


def test_pure_hashes_match_hashlib() -> None:
    payloads = [b"", b"abc", b"a" * 55, b"a" * 56, b"a" * 64, b"a" * 200]
    for payload in payloads:
        assert _md5_hash(payload) == hashlib.md5(payload).digest()
        assert _sha1_hash(payload) == hashlib.sha1(payload).digest()
        assert _sha256_hash(payload) == hashlib.sha256(payload).digest()


def test_glue_padding_shape() -> None:
    for total in (0, 1, 55, 56, 60, 64, 119, 120):
        glue_md = glue_padding_md(total)
        assert (total + len(glue_md)) % 64 == 0
        assert glue_md[0:1] == b"\x80"
        assert glue_md[-8:] == (total * 8).to_bytes(8, "little")
        glue_sha = glue_padding_sha(total)
        assert (total + len(glue_sha)) % 64 == 0
        assert glue_sha[0:1] == b"\x80"
        assert glue_sha[-8:] == (total * 8).to_bytes(8, "big")


def test_md5_extend_basic() -> None:
    _check_extend("md5", b"s3cr3t-key-1234", b"amount=100&to=alice", b"&to=mallory")


def test_sha1_extend_basic() -> None:
    _check_extend("sha1", b"s3cr3t-key-1234", b"amount=100&to=alice", b"&to=mallory")


def test_sha256_extend_basic() -> None:
    _check_extend("sha256", b"s3cr3t-key-1234", b"amount=100&to=alice", b"&to=mallory")


def test_extend_glue_crosses_block_boundary() -> None:
    # Total length 60: only 4 bytes left in the block, fewer than the 9 bytes
    # the padding minimally needs (0x80 + 8-byte length), so the glue padding
    # spills into a second block (68 bytes of glue).
    secret = b"k" * 16
    msg = b"m" * 44
    assert len(secret) + len(msg) == 60
    assert len(glue_padding_md(60)) == 68
    assert len(glue_padding_sha(60)) == 68
    for algo in ("md5", "sha1", "sha256"):
        _check_extend(algo, secret, msg, b"&admin=true")


def test_extend_empty_append() -> None:
    for algo in ("md5", "sha1", "sha256"):
        _check_extend(algo, b"secret", b"data", b"")


def test_extend_long_append_spanning_blocks() -> None:
    for algo in ("md5", "sha1", "sha256"):
        _check_extend(algo, b"key", b"msg", b"x" * 150)


def test_length_extend_dispatcher() -> None:
    secret, msg, append = b"topsecret", b"user=bob", b"&role=admin"
    for algo in ("md5", "sha1", "sha256"):
        orig = hashlib.new(algo, secret + msg).hexdigest()
        via_dispatch = length_extend(algo, orig, len(secret) + len(msg), append)
        direct = _EXTENDERS[algo](orig, len(secret) + len(msg), append)
        assert via_dispatch == direct


def test_length_extend_rejects_unknown_algorithm() -> None:
    raised = False
    try:
        length_extend("sha512", "00" * 32, 10, b"x")
    except ValueError:
        raised = True
    assert raised
