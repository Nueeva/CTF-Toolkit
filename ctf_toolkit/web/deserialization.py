from __future__ import annotations

import pickletools
import re
from typing import Any


def pickle_inspect_opcodes(data: bytes) -> list[tuple[str, Any, int | None]]:
    """
    Safely disassemble a Python `pickle` byte stream using `pickletools.genops`
    without executing `pickle.loads()`. Returns `(opcode_name, arg, pos)` tuples.
    """
    ops: list[tuple[str, Any, int | None]] = []
    for opcode, arg, pos in pickletools.genops(data):
        ops.append((opcode.name, arg, pos))
    return ops


def build_php_serialized_object(
    class_name: str,
    properties: dict[str, Any],
    bypass_wakeup: bool = False,
) -> str:
    """
    Construct a PHP `serialize()` object representation `O:<len>:"<class>":<count>:{...}`.
    If `bypass_wakeup=True`, increments the declared property count by 1 (CVE-2016-7124 `__wakeup` bypass).
    """
    def _ser_val(v: Any) -> str:
        if v is None:
            return "N;"
        if isinstance(v, bool):
            return f"b:{1 if v else 0};"
        if isinstance(v, int):
            return f"i:{v};"
        if isinstance(v, str):
            b_len = len(v.encode("utf-8"))
            return f's:{b_len}:"{v}";'
        if isinstance(v, dict):
            inner = "".join(_ser_val(k) + _ser_val(val) for k, val in v.items())
            return f"a:{len(v)}:{{{inner}}}"
        if isinstance(v, (list, tuple)):
            inner = "".join(_ser_val(idx) + _ser_val(val) for idx, val in enumerate(v))
            return f"a:{len(v)}:{{{inner}}}"
        s = str(v)
        return f's:{len(s.encode("utf-8"))}:"{s}";'

    body = "".join(_ser_val(str(k)) + _ser_val(v) for k, v in properties.items())
    prop_count = len(properties) + (1 if bypass_wakeup else 0)
    cls_len = len(class_name.encode("utf-8"))
    return f'O:{cls_len}:"{class_name}":{prop_count}:{{{body}}}'


def parse_php_serialized(text: str) -> dict[str, Any]:
    """Extract class names, string literals, and integer properties from a PHP serialized string."""
    classes = re.findall(r'O:\d+:"([^"]+)"', text)
    strings = re.findall(r's:\d+:"([^"]*)"', text)
    ints = [int(x) for x in re.findall(r"i:(-?\d+);", text)]
    return {
        "classes": classes,
        "strings": strings,
        "ints": ints,
    }
