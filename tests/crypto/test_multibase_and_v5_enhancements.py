from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ctf_toolkit.binex import glibc_safe_link_demangle, glibc_safe_link_mangle
from ctf_toolkit.cases import operations
from ctf_toolkit.cases.store import Workspace
from ctf_toolkit.crypto.coppersmith import coppersmith_factor_high_bits
from ctf_toolkit.crypto.dlog_engine import ec_mul, ec_pohlig_hellman_coords
from ctf_toolkit.crypto.encoding import (
    ascii85_decode,
    ascii85_encode,
    base16_decode,
    base16_encode,
    base32_decode,
    base32_encode,
    base32hex_decode,
    base32hex_encode,
    base36_decode,
    base36_encode,
    base45_decode,
    base45_encode,
    base58_decode,
    base58_encode,
    base58_ripple_decode,
    base58_ripple_encode,
    base62_decode,
    base62_encode,
    base64_decode_std,
    base64_encode_std,
    base64url_decode,
    base64url_encode,
    base85_decode,
    base85_encode,
    base91_decode,
    base91_encode,
    base_n_decode,
    base_n_encode,
    smart_decode,
    z85_decode,
    z85_encode,
)
from ctf_toolkit.pipeline import run_recipe
from ctf_toolkit.ui.magic_solver import solve_magic
from ctf_toolkit.utils.flag_manager import get_flag_manager
from ctf_toolkit.web.helpers import b64url_encode, decode_flask_session_cookie


class TestMultiBaseAndV5Enhancements(unittest.TestCase):
    def test_all_base_codecs_roundtrip(self) -> None:
        payload = b"FLAG{all_base_formats_supported_v5!}"
        codecs_to_test = [
            ("base16", base16_encode, base16_decode),
            ("base32", base32_encode, base32_decode),
            ("base32hex", base32hex_encode, base32hex_decode),
            ("base36", base36_encode, base36_decode),
            ("base45", base45_encode, base45_decode),
            ("base58", base58_encode, base58_decode),
            ("base58_ripple", base58_ripple_encode, base58_ripple_decode),
            ("base62", base62_encode, base62_decode),
            ("base64", base64_encode_std, base64_decode_std),
            ("base64url", base64url_encode, base64url_decode),
            ("base85", base85_encode, base85_decode),
            ("ascii85", ascii85_encode, ascii85_decode),
            ("z85", z85_encode, z85_decode),
            ("base91", base91_encode, base91_decode),
        ]
        for name, enc_fn, dec_fn in codecs_to_test:
            encoded = enc_fn(payload)
            decoded = dec_fn(encoded)
            self.assertEqual(decoded, payload, f"Round-trip failed for {name}")

        for radix in (7, 12, 20, 36):
            enc_n = base_n_encode(payload, radix)
            dec_n = base_n_decode(enc_n, radix)
            self.assertEqual(dec_n, payload, f"Round-trip failed for base-{radix}")

    def test_recipe_pipeline_all_bases(self) -> None:
        raw = b"FLAG{recipe_multibase_chain_ok!}"
        pipeline = (
            "b64e | b64d | b64url_e | b64url_d | b32e | b32d | b32hex_e | b32hex_d | "
            "b36e | b36d | b45e | b45d | b58e | b58d | b58_ripple_e | b58_ripple_d | "
            "b62e | b62d | b85e | b85d | a85e | a85d | z85e | z85d | b91e | b91d | b16e | b16d"
        )
        out = run_recipe(pipeline, raw)
        self.assertEqual(out, raw)

    def test_magic_solver_cracks_non_base64_bases(self) -> None:
        target = b"FLAG{magic_multi_base_victory}"
        for encode_recipe in ("b32hex_e", "b58e", "b62e", "b45e", "b85e", "b91e", "z85e"):
            cipher = run_recipe(encode_recipe, target)
            cipher_bytes = cipher.encode() if isinstance(cipher, str) else cipher
            best_data, best_path, best_score, _ = solve_magic(cipher_bytes, max_depth=2)
            self.assertGreaterEqual(best_score, 10000.0, f"Magic solver failed on {encode_recipe}")
            self.assertIn(b"FLAG{magic_multi_base_victory}", best_data)

    def test_case_workbench_multibase_recipes_and_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Workspace.create(Path(tmp) / "case")
            # 1. Hex provenance: 1 output byte -> 2 hex symbols
            hex_art = ws.add("sample.hex", b"46 4c 41 47")
            tx_hex = operations.transform(ws, hex_art["id"], "hex_decode")
            src_hex = operations.source_region(ws, tx_hex["artifacts"][0], 1, 3)
            self.assertEqual(src_hex, {"artifact_id": hex_art["id"], "kind": "bytes", "start": 3, "stop": 8})

            # 2. Base32 provenance: 5 output bytes -> 8 Base32 symbols
            b32_art = ws.add("sample.b32", base32_encode(b"HELLO_WORLD").encode())
            tx_b32 = operations.transform(ws, b32_art["id"], "b32d")
            src_b32 = operations.source_region(ws, tx_b32["artifacts"][0], 0, 5)
            self.assertEqual(src_b32, {"artifact_id": b32_art["id"], "kind": "bytes", "start": 0, "stop": 8})

            # 3. Chained multi-base transform & deterministic replay verification
            b58_art = ws.add("sample.txt", b"FLAG{case_multibase}")
            tx_chain = operations.transform(ws, b58_art["id"], "b58e | b58d | b62e | b62d")
            final_blob = ws.blob(ws.artifact(tx_chain["artifacts"][-1]))
            self.assertEqual(final_blob, b"FLAG{case_multibase}")
            ver = operations.verify(ws, replay=True)
            self.assertTrue(ver["ok"], ver["errors"])

    def test_dynamic_flag_manager_unification(self) -> None:
        fm = get_flag_manager()
        fm.add_template("NUEEVACTF_TEST", r"NUEEVACTF\{[^}\n]+\}", priority=99)
        try:
            custom_flag = b"NUEEVACTF{dynamic_flag_sync_works}"
            enc = base58_encode(custom_flag).encode()
            best_data, _, best_score, _ = solve_magic(enc, max_depth=2)
            self.assertGreaterEqual(best_score, 10000.0)
            self.assertEqual(best_data, custom_flag)
            scanned = run_recipe("b58d | flag_scan", enc)
            self.assertEqual(scanned, "NUEEVACTF{dynamic_flag_sync_works}")
        finally:
            fm.remove_template("NUEEVACTF_TEST")

    def test_ec_pohlig_hellman_and_coppersmith_high_bits(self) -> None:
        # Elliptic curve y^2 = x^3 + 2x + 3 over F_97, point P=(3, 6) has order 5 or divisor of #E=100
        a, b, p = 2, 3, 97
        px, py = 3, 6
        secret_k = 4
        qx, qy = ec_mul(a, b, p, secret_k, px, py)
        recovered_k = ec_pohlig_hellman_coords(a, b, p, px, py, qx, qy, order=5)
        self.assertEqual(recovered_k, secret_k)

        # Coppersmith partial prime exposure
        p_prime = (1 << 127) - 1  # Mersenne prime M127
        q_prime = (1 << 107) - 1  # Mersenne prime M107
        n_mod = p_prime * q_prime
        unknown_bits = 12
        p_approx = (p_prime >> unknown_bits) << unknown_bits
        factored = coppersmith_factor_high_bits(n_mod, p_approx, unknown_bits)
        self.assertEqual(factored, (q_prime, p_prime))

    def test_glibc_safe_linking_and_flask_cookie_inspector(self) -> None:
        heap_slot = 0x5555555592A0
        target_ptr = 0x5555555592C0
        mangled = glibc_safe_link_mangle(target_ptr, heap_slot)
        self.assertEqual(glibc_safe_link_demangle(mangled, heap_slot), target_ptr)
        self.assertEqual(glibc_safe_link_demangle(mangled), target_ptr)

        cookie = f"{b64url_encode(b'{\"admin\":true,\"user\":\"nueeva\"}')}.Z0abcA.sig123"
        info = decode_flask_session_cookie(cookie)
        self.assertFalse(info["compressed"])
        self.assertEqual(info["payload"], {"admin": True, "user": "nueeva"})


if __name__ == "__main__":
    unittest.main()
