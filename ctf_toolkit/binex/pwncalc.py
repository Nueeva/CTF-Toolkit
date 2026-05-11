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


def describe_integer_bounds(value: int) -> list[dict[str, object]]:
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
            }
        )
    return results
