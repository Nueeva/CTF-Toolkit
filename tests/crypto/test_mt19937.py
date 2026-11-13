import random

import pytest

from ctf_toolkit.crypto.mt19937 import (
    MT19937Clone,
    _temper,
    clone_from_outputs,
    predict_next,
    untemper,
)


def _draw(rng: random.Random, count: int) -> list[int]:
    return [rng.getrandbits(32) for _ in range(count)]


def test_untemper_roundtrip() -> None:
    rng = random.Random(1234)
    for _ in range(50):
        out = rng.getrandbits(32)
        # Re-tempering the recovered state word must reproduce the
        # original output exactly.
        assert _temper(untemper(out)) == out


def test_clone_predicts_future_outputs_seed_a() -> None:
    rng = random.Random(42)
    leaked = _draw(rng, 624)
    expected = _draw(rng, 200)
    clone = MT19937Clone(leaked)
    predicted = [clone.next() for _ in range(200)]
    assert predicted == expected


def test_clone_predicts_future_outputs_seed_b() -> None:
    rng = random.Random(20261113)
    leaked = _draw(rng, 624)
    expected = _draw(rng, 500)
    clone = clone_from_outputs(leaked)
    predicted = [clone.next() for _ in range(500)]
    assert predicted == expected


def test_clone_uses_only_first_624_outputs() -> None:
    rng = random.Random(7)
    leaked = _draw(rng, 674)
    # Clone gets the full list but must position itself after the
    # first 624 outputs, so its predictions equal leaked[624:].
    clone = MT19937Clone(leaked)
    assert [clone.next() for _ in range(50)] == leaked[624:]


def test_predict_next() -> None:
    rng = random.Random(987654321)
    leaked = _draw(rng, 624)
    expected = _draw(rng, 100)
    assert predict_next(leaked, 100) == expected


def test_clone_getrandbits_matches_cpython() -> None:
    rng = random.Random(31337)
    leaked = _draw(rng, 624)
    clone = MT19937Clone(leaked)
    for k in (1, 8, 16, 31, 32):
        assert clone.getrandbits(k) == rng.getrandbits(k)


def test_clone_requires_624_outputs() -> None:
    rng = random.Random(1)
    leaked = _draw(rng, 623)
    with pytest.raises(ValueError):
        MT19937Clone(leaked)
    with pytest.raises(ValueError):
        clone_from_outputs(leaked)
    with pytest.raises(ValueError):
        predict_next(leaked, 1)


def test_getrandbits_rejects_k_over_32() -> None:
    rng = random.Random(5)
    clone = MT19937Clone(_draw(rng, 624))
    with pytest.raises(ValueError):
        clone.getrandbits(33)
