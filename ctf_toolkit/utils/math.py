from __future__ import annotations

from typing import Iterable


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m


def crt(remainders: Iterable[int], moduli: Iterable[int]) -> tuple[int, int]:
    rs = list(remainders)
    ns = list(moduli)
    if len(rs) != len(ns) or not rs:
        raise ValueError("invalid CRT input")

    x = 0
    n_prod = 1
    for n in ns:
        n_prod *= n

    for r_i, n_i in zip(rs, ns):
        p = n_prod // n_i
        inv = modinv(p % n_i, n_i)
        x += r_i * inv * p

    return x % n_prod, n_prod


def integer_nthroot(value: int, n: int) -> tuple[int, bool]:
    if value < 0 or n <= 0:
        raise ValueError("invalid integer_nthroot input")
    if value in (0, 1):
        return value, True

    low, high = 0, value
    while low <= high:
        mid = (low + high) // 2
        power = mid**n
        if power == value:
            return mid, True
        if power < value:
            low = mid + 1
        else:
            high = mid - 1
    return high, high**n == value


def collatz_stopping_time(n: int) -> int:
    """Calculate the number of steps to reach 1 in the 3n + 1 (Collatz) sequence."""
    if n <= 0:
        raise ValueError("n must be a positive integer")
    steps = 0
    while n != 1:
        if n % 2 == 0:
            n //= 2
        else:
            n = 3 * n + 1
        steps += 1
    return steps


def fibonacci_index(n: int, max_terms: int = 300) -> int:
    """Return the 0-based index of Fibonacci number n, or -1 if not found."""
    fibs = [0, 1]
    while len(fibs) < max_terms and fibs[-1] < n:
        fibs.append(fibs[-1] + fibs[-2])
    return fibs.index(n) if n in fibs else -1


def cellular_automaton_xor(init_cells: str | list[int], steps: int) -> bytes:
    """Evolve 1D binary cellular automaton under XOR rule: cell[i] = cell[i] ^ cell[i-1] (cell[-1]=0)."""
    if isinstance(init_cells, str):
        cells = [int(c) for c in init_cells if c in "01"]
    else:
        cells = list(init_cells)

    n = len(cells)
    curr = cells[:]
    for _ in range(steps):
        nxt = [0] * n
        nxt[0] = curr[0] ^ 0
        for i in range(1, n):
            nxt[i] = curr[i] ^ curr[i - 1]
        curr = nxt

    bits_str = "".join(str(b) for b in curr)
    byte_vals = [int(bits_str[i : i + 8], 2) for i in range(0, len(bits_str) - 7, 8)]
    return bytes(byte_vals)


def solve_gf2_system(A_rows: list[str] | list[list[int]], b_vec: str | list[int]) -> bytes:
    """Solve linear system A * x = b over GF(2) using Gaussian elimination and return x as bytes."""
    if isinstance(b_vec, str):
        b_list = [int(c) for c in b_vec if c in "01"]
    else:
        b_list = list(b_vec)

    n = len(b_list)
    rows: list[int] = []
    for i in range(n):
        row = A_rows[i]
        if isinstance(row, str):
            row_int = int(row.strip(), 2) << 1
        else:
            row_int = int("".join(str(x) for x in row), 2) << 1
        row_int |= int(b_list[i])
        rows.append(row_int)

    for col in range(n):
        bit_pos = n - col
        pivot = -1
        for r in range(col, n):
            if (rows[r] >> bit_pos) & 1:
                pivot = r
                break
        if pivot == -1:
            raise ValueError(f"Matrix is singular at column {col}")

        rows[col], rows[pivot] = rows[pivot], rows[col]

        for r in range(n):
            if r != col and ((rows[r] >> bit_pos) & 1):
                rows[r] ^= rows[col]

    x_bits = ["1" if rows[col] & 1 else "0" for col in range(n)]
    bits_str = "".join(x_bits)
    byte_vals = [int(bits_str[i : i + 8], 2) for i in range(0, len(bits_str) - 7, 8)]
    return bytes(byte_vals)

