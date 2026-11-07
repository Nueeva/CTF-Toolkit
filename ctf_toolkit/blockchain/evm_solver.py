from __future__ import annotations

MOD_256: int = 2**256


def solve_evm_affine_constraint(mul_val: int, add_val: int, mod: int = MOD_256) -> int:
    """Compute the modular value (mul_val * k + add_val) % mod."""
    return (mul_val + add_val) % mod


def invert_evm_minivm(target: int, mask: int, add_c: int, mod: int = MOD_256) -> int:
    """Invert EVM mini VM transformation: target = (k + add_c) ^ mask."""
    intermediate = target ^ mask
    return (intermediate - add_c) % mod


def xor_bytes32(*keys: bytes) -> bytes:
    """Compute bitwise XOR across multiple 32-byte chunks."""
    result = bytearray(32)
    for k in keys:
        clean = k[:32].ljust(32, b"\x00")
        for i in range(32):
            result[i] ^= clean[i]
    return bytes(result)
