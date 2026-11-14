"""Contract probe: every catalog function must be callable through /api/call.

The web workbench dispatches by name and coerces JSON scalars into the declared
types. A solver that only takes a dataclass (EllipticCurve, SolveContext) or a
`bytes` argument silently fails there even though the Python API works. This
probe exercises the dispatcher's coercion layer directly, without a socket.

Run:  python tests/integration/test_web_api_contract.py
"""

from __future__ import annotations

import inspect
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from ctf_toolkit.ui.palette import build_tool_catalog
from ctf_toolkit.ui.web_server import _coerce_param

_JSON_SCALARS = (int, float, str, bool)


def _dispatchable(fn) -> tuple[bool, str]:
    """True when every parameter can be built from a JSON scalar."""
    try:
        sig = inspect.signature(fn)
    except (ValueError, TypeError) as exc:
        return False, f"no signature: {exc}"
    for param in sig.parameters.values():
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            continue
        if param.default is not inspect.Parameter.empty:
            continue
        ann = str(param.annotation)
        if ann in ("inspect._empty", ""):
            return False, f"unannotated required param {param.name!r}"
        if ann.startswith("SolveContext") or ann.startswith("EllipticCurve"):
            return False, f"dataclass-only param {param.name!r}: {ann}"
    return True, ""


def test_coercion_handles_every_declared_type():
    def sample(a: int, b: float, c: str, d: bytes, e: bool, f: list[int], g: dict) -> None:
        pass

    params = inspect.signature(sample).parameters
    assert _coerce_param("7", params["a"]) == 7
    assert _coerce_param("1.5", params["b"]) == 1.5
    assert _coerce_param("hi", params["c"]) == "hi"
    assert _coerce_param("hi", params["d"]) == b"hi"
    assert _coerce_param("true", params["e"]) is True
    assert _coerce_param("[1,2]", params["f"]) == [1, 2]
    assert _coerce_param('{"k":1}', params["g"]) == {"k": 1}


def test_every_catalog_function_is_reachable_from_the_api():
    catalog = build_tool_catalog(force_refresh=True)
    assert len(catalog) > 600, f"catalog unexpectedly small: {len(catalog)}"

    blocked = []
    for tool in catalog:
        ok, why = _dispatchable(tool["func"])
        if not ok:
            blocked.append(f"{tool['name']} ({tool['module']}): {why}")

    # Every catalog entry must be invocable from the JSON dispatcher. Solvers
    # whose API needs an EllipticCurve object must ship a flat twin
    # (smart_attack_coords / ec_mul / ...) instead of exposing the class path.
    blocked = []
    for tool in catalog:
        ok, why = _dispatchable(tool["func"])
        if not ok:
            blocked.append(f"{tool['name']} ({tool['module']}): {why}")

    assert not blocked, "catalog entries unreachable from /api/call:\n" + "\n".join(blocked)


def test_json_encoder_round_trips_solver_outputs():
    from ctf_toolkit.crypto.crc_forge import forge_crc32
    from ctf_toolkit.crypto.length_extension import md5_extend

    def encode(value):
        if isinstance(value, (bytes, bytearray)):
            raw = bytes(value)
            return {"hex": raw.hex(), "utf8": raw.decode("utf-8", errors="replace")}
        if isinstance(value, dict):
            return {str(k): encode(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [encode(v) for v in value]
        if hasattr(value, "__dataclass_fields__"):
            return {k: encode(getattr(value, k)) for k in value.__dataclass_fields__}
        return value

    crc = forge_crc32(b"abcdefgh", 0x0BADF00D)
    payload = encode({"result": crc})
    assert bytes.fromhex(payload["result"]["data"]["hex"]) == crc.data

    digest, tail = md5_extend("d41d8cd98f00b204e9800998ecf8427e", 0, b"x")
    encoded = encode({"digest": digest, "tail": tail})
    assert isinstance(encoded["tail"], dict) and encoded["tail"]["hex"]
    json.dumps(encoded)  # must not raise


if __name__ == "__main__":
    test_coercion_handles_every_declared_type()
    test_every_catalog_function_is_reachable_from_the_api()
    test_json_encoder_round_trips_solver_outputs()
    print("web API contract: 3/3 OK")
