from __future__ import annotations

from ctf_toolkit.utils.math import modinv


def lcg_next(x: int, a: int, c: int, m: int) -> int:
    return (a * x + c) % m


def lcg_generate(seed: int, a: int, c: int, m: int, count: int) -> list[int]:
    values: list[int] = []
    x = seed
    for _ in range(count):
        x = lcg_next(x, a, c, m)
        values.append(x)
    return values


def recover_lcg_params_known_mod(outputs: list[int], m: int) -> tuple[int, int]:
    if len(outputs) < 3:
        raise ValueError("at least 3 outputs are required")

    x0, x1, x2 = outputs[:3]
    denom = (x1 - x0) % m
    if denom == 0:
        raise ValueError("cannot recover parameters: consecutive outputs are identical modulo m")

    a = ((x2 - x1) * modinv(denom, m)) % m
    c = (x1 - a * x0) % m
    return a, c


class GlibcRandom:
    """
    Emulate the standard glibc random()/rand() generator (TYPE_3 additive feedback generator).
    Matches Linux srand(seed) / rand() outputs.
    """

    def __init__(self, seed: int = 1) -> None:
        self.state = [0] * 34
        self.state[0] = seed & 0xFFFFFFFF
        for i in range(1, 31):
            val = (16807 * self.state[i - 1]) % 2147483647
            if val < 0:
                val += 2147483647
            self.state[i] = val
        for i in range(31, 34):
            self.state[i] = self.state[i - 31]
        self.fptr = 3
        self.rptr = 0
        for _ in range(310):
            self.next()

    def next(self) -> int:
        val = (self.state[self.fptr] + self.state[self.rptr]) & 0xFFFFFFFF
        self.state[self.fptr] = val
        res = (val >> 1) & 0x7FFFFFFF
        self.fptr = (self.fptr + 1) % 31
        self.rptr = (self.rptr + 1) % 31
        return res


def glibc_rand_generate(seed: int, count: int = 10) -> list[int]:
    """
    Generate the first `count` outputs of glibc rand() given the initial seed.
    """
    rng = GlibcRandom(seed)
    return [rng.next() for _ in range(count)]


def glibc_rand_predict(outputs: list[int], count: int = 10) -> list[int]:
    """
    Predict future glibc rand() outputs given at least 31 consecutive observed outputs.
    Formula: r[i] = (r[i-31] + r[i-3] + carry) & 0x7fffffff
    """
    if len(outputs) < 31:
        raise ValueError("at least 31 outputs are required to predict glibc rand()")

    state = list(outputs[-31:])
    predictions: list[int] = []
    for _ in range(count):
        # In glibc TYPE_3, the next 31-bit word is (state[-31] + state[-3]) mod 2^31 (ignoring lowest carry or with standard add)
        val = (state[-31] + state[-3]) & 0x7FFFFFFF
        predictions.append(val)
        state.append(val)
    return predictions
