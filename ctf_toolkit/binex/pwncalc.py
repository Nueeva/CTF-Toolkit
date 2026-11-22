from __future__ import annotations

from ctf_toolkit.binex.cyclic import cyclic_create, cyclic_find


def _unsigned_wrap(value: int, bits: int) -> int:
    mask = (1 << bits) - 1
    return value & mask


def _signed_wrap(value: int, bits: int) -> int:
    unsigned = _unsigned_wrap(value, bits)
    sign_bit = 1 << (bits - 1)
    return unsigned - (1 << bits) if unsigned & sign_bit else unsigned


def _signed_bounds(bits: int) -> tuple[int, int]:
    return -(1 << (bits - 1)), (1 << (bits - 1)) - 1


def _unsigned_bounds(bits: int) -> tuple[int, int]:
    return 0, (1 << bits) - 1


def _bypass_underflow_check(value: int, bits: int, limit: int) -> bool:
    signed_value = _signed_wrap(value, bits)
    unsigned_value = _unsigned_wrap(value, bits)
    return signed_value <= limit < unsigned_value


def describe_integer_bounds(value: int, limit: int = 67) -> list[dict[str, object]]:
    specs = [
        ("i32", 32, True),
        ("u32", 32, False),
        ("i64", 64, True),
        ("u64", 64, False),
    ]
    results: list[dict[str, object]] = []
    for label, bits, signed in specs:
        unsigned = _unsigned_wrap(value, bits)
        if signed:
            min_val, max_val = _signed_bounds(bits)
            display_value = _signed_wrap(value, bits)
        else:
            min_val, max_val = _unsigned_bounds(bits)
            display_value = unsigned
        results.append(
            {
                "label": label,
                "bits": bits,
                "signed": signed,
                "value": display_value,
                "unsigned": unsigned,
                "hex": f"0x{unsigned:0{bits // 4}x}",
                "min": min_val,
                "max": max_val,
                "overflow": value > max_val,
                "underflow": value < min_val,
                "wrapped": display_value != value,
                "bypass_check": signed and _bypass_underflow_check(value, bits, limit),
                "limit": limit,
            }
        )
    return results


def glibc_safe_link_mangle(ptr: int, pos_addr: int) -> int:
    """Compute glibc >= 2.32 safe-linking mangled pointer: `ptr ^ (pos_addr >> 12)`."""
    return (ptr ^ (pos_addr >> 12)) & ((1 << 64) - 1)


def glibc_safe_link_demangle(mangled_ptr: int, pos_addr: int = 0) -> int:
    """Recover original pointer from glibc >= 2.32 safe-linking mangled value.

    If `pos_addr` (the address where the pointer is stored) is known, computes
    `mangled_ptr ^ (pos_addr >> 12)`. If `pos_addr == 0`, iteratively unmasks
    12-bit chunks from MSB to LSB assuming same-page heap locality.
    """
    val = mangled_ptr & ((1 << 64) - 1)
    if pos_addr:
        return val ^ (pos_addr >> 12)
    plain = 0
    for i in range(1, 6):
        bits = 64 - 12 * i
        if bits < 0:
            bits = 0
        plain = ((val ^ (plain >> 12)) >> bits) << bits
    return plain
