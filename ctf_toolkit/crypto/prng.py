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
        raise ValueError("insufficient data to recover multiplier a")

    a = ((x2 - x1) * modinv(denom, m)) % m
    c = (x1 - a * x0) % m
    return a, c
