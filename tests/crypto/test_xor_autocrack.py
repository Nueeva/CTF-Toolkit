"""Known-answer tests for ctf_toolkit.crypto.xor_autocrack."""

from __future__ import annotations

import pytest

from ctf_toolkit.crypto.xor_autocrack import (
    crack_repeating_key_xor,
    crack_single_byte_xor,
    guess_key_lengths,
)

_PARAGRAPH = (
    b"The quick brown fox jumps over the lazy dog while the morning sun "
    b"rises over the quiet village. People walk to the market with baskets "
    b"of bread, fruit, and fresh vegetables, talking about the weather and "
    b"the news of the day. A gentle wind moves through the trees, and the "
    b"sound of birds fills the air as children play near the river. In the "
    b"afternoon, farmers return from the fields and gather in the square to "
    b"share stories about the harvest, the rain, and the work that waits "
    b"for them tomorrow. When evening comes, families sit together for "
    b"dinner and speak of simple things: the price of rice, the health of "
    b"their parents, and the plans they have for the coming season ahead."
)


def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def test_single_byte_xor_known_answer() -> None:
    pt = b"the secret message is hidden in plain sight and nobody noticed"
    ct = _xor(pt, b"\x42")
    key_byte, recovered, _score = crack_single_byte_xor(ct)
    assert key_byte == 0x42
    assert recovered == pt


def test_guess_key_lengths_ranks_true_length() -> None:
    ct = _xor(_PARAGRAPH, b"KEY")
    assert 3 in guess_key_lengths(ct, top=5)


def test_crack_repeating_key_short_key() -> None:
    ct = _xor(_PARAGRAPH, b"KEY")
    key, recovered, _score = crack_repeating_key_xor(ct)
    assert recovered == _PARAGRAPH
    assert key == b"KEY"


def test_crack_repeating_key_ice() -> None:
    pt = _PARAGRAPH * 2
    ct = _xor(pt, b"ICE")
    key, recovered, _score = crack_repeating_key_xor(ct)
    assert recovered == pt
    assert key == b"ICE"


def test_crack_repeating_key_ten_byte_key() -> None:
    pt = _PARAGRAPH * 2
    ct = _xor(pt, b"s3cr3t-k3y")
    key, recovered, _score = crack_repeating_key_xor(ct)
    assert recovered == pt
    assert key == b"s3cr3t-k3y"


def test_crack_repeating_key_rejects_tiny_input() -> None:
    with pytest.raises(ValueError):
        crack_repeating_key_xor(b"\x01\x02\x03")
