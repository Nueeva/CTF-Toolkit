"""MT19937 (Mersenne Twister) state recovery / cloning.

Python's :mod:`random` module is MT19937. If a challenge leaks 624
consecutive 32-bit outputs (e.g. via ``getrandbits(32)``), the full
internal state can be reconstructed by inverting the tempering
transform, after which every future output is predictable.

Pure stdlib; no dependencies.
"""
from __future__ import annotations

_MASK32 = 0xFFFFFFFF

# Standard MT19937 parameters (same as CPython's _random module).
_N = 624
_M = 397
_MATRIX_A = 0x9908B0DF
_UPPER_MASK = 0x80000000
_LOWER_MASK = 0x7FFFFFFF

# Tempering constants.
_TEMPER_B = 0x9D2C5680
_TEMPER_C = 0xEFC60000


def _undo_right_shift_xor(y: int, shift: int) -> int:
    """Invert ``y = x ^ (x >> shift)`` on 32-bit values.

    The top ``shift`` bits of ``y`` already equal those of ``x``; each
    iteration recovers another ``shift`` bits downward.
    """
    x = y
    for _ in range(0, 32, shift):
        x = y ^ (x >> shift)
    return x & _MASK32


def _undo_left_shift_xor_mask(y: int, shift: int, mask: int) -> int:
    """Invert ``y = x ^ ((x << shift) & mask)`` on 32-bit values.

    Mirror of the right-shift case: bits are recovered upward from the
    least significant side.
    """
    x = y
    for _ in range(0, 32, shift):
        x = y ^ ((x << shift) & mask)
    return x & _MASK32


def untemper(y: int) -> int:
    """Invert the MT19937 tempering transform.

    Given one tempered 32-bit output, return the raw state word that
    produced it. Applies the four tempering steps in reverse order.
    """
    y &= _MASK32
    y = _undo_right_shift_xor(y, 18)
    y = _undo_left_shift_xor_mask(y, 15, _TEMPER_C)
    y = _undo_left_shift_xor_mask(y, 7, _TEMPER_B)
    y = _undo_right_shift_xor(y, 11)
    return y


def _temper(x: int) -> int:
    """Apply the MT19937 tempering transform to a raw state word."""
    y = x & _MASK32
    y ^= y >> 11
    y ^= (y << 7) & _TEMPER_B
    y ^= (y << 15) & _TEMPER_C
    y ^= y >> 18
    return y & _MASK32


class MT19937Clone:
    """A cloned MT19937 generator reconstructed from leaked outputs.

    ``outputs`` must contain at least 624 consecutive 32-bit outputs of
    the target generator; the first 624 are untempered into the state
    array. The clone is positioned exactly where the target generator
    was after producing those 624 values, so :meth:`next` yields the
    values the target will produce next.
    """

    def __init__(self, outputs: list[int]) -> None:
        if len(outputs) < _N:
            raise ValueError(
                f"at least {_N} consecutive outputs are required to clone "
                f"MT19937 state, got {len(outputs)}"
            )
        self._state: list[int] = [untemper(o) for o in outputs[:_N]]
        # Index at _N forces a twist before the first extraction,
        # matching the state of the source generator.
        self._index = _N

    def _twist(self) -> None:
        """Regenerate the state array (the MT19937 twist operation)."""
        state = self._state
        for i in range(_N):
            x = (state[i] & _UPPER_MASK) | (state[(i + 1) % _N] & _LOWER_MASK)
            x_a = x >> 1
            if x & 1:
                x_a ^= _MATRIX_A
            state[i] = state[(i + _M) % _N] ^ x_a
        self._index = 0

    def next(self) -> int:
        """Return the next predicted 32-bit output of the target."""
        if self._index >= _N:
            self._twist()
        value = _temper(self._state[self._index])
        self._index += 1
        return value

    def getrandbits(self, k: int) -> int:
        """Predict ``random.Random.getrandbits(k)`` for ``k <= 32``.

        CPython consumes one full 32-bit word per call and returns its
        top ``k`` bits.
        """
        if k > 32:
            raise ValueError("getrandbits clone only supports k <= 32")
        if k <= 0:
            return 0
        return self.next() >> (32 - k)


def clone_from_outputs(outputs: list[int]) -> MT19937Clone:
    """Build an :class:`MT19937Clone` from >= 624 consecutive outputs."""
    return MT19937Clone(outputs)


def predict_next(outputs: list[int], count: int) -> list[int]:
    """Clone from ``outputs`` and return the next ``count`` values."""
    clone = MT19937Clone(outputs)
    return [clone.next() for _ in range(count)]
