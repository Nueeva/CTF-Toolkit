from __future__ import annotations

import ast
import io
import pickle
import plistlib
import re
import unittest
import warnings
import wave
import zlib
from pathlib import Path

import numpy as np
from Crypto.PublicKey import RSA


class TestV4AuditRemediation(unittest.TestCase):
    def test_all_python_files_compile_cleanly(self) -> None:
        root = Path(__file__).resolve().parents[2] / "ctf_toolkit"
        py_files = list(root.rglob("*.py"))
        self.assertGreaterEqual(len(py_files), 100)
        for py in py_files:
            src = py.read_text(encoding="utf-8")
            tree = ast.parse(src, filename=str(py))
            compile(tree, filename=str(py), mode="exec")

    def test_command_palette_indexes_over_500_functions(self) -> None:
        from ctf_toolkit.ui.palette import build_tool_catalog, fuzzy_search_tools

        catalog = build_tool_catalog(force_refresh=True)
        self.assertGreaterEqual(len(catalog), 500)
        names = {item["name"] for item in catalog}
        for expected in (
            "aes_ecb_decrypt",
            "autokey_decrypt",
            "solve_rsa_auto",
            "lll_reduce",
            "ecc_smarts_attack",
            "jwt_crack_hs256",
            "decode_protobuf_raw",
            "carve_embedded_files",
            "analyze_wasm_binary",
        ):
            self.assertIn(expected, names)
        res = fuzzy_search_tools("solve_rsa_auto", catalog)
        self.assertTrue(res and res[0]["name"] == "solve_rsa_auto")

    def test_des_no_deprecation_warning(self) -> None:
        from ctf_toolkit.crypto.des import des_ecb_decrypt, des_ecb_encrypt, triple_des_ecb_decrypt

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            key = b"8bytekey"
            pt = b"GETSFLAG{des_ok}"
            ct = des_ecb_encrypt(pt, key)
            dec = des_ecb_decrypt(ct, key)
            self.assertEqual(dec, pt)
            dep_warnings = [item for item in w if "Deprecation" in item.category.__name__]
            self.assertEqual(len(dep_warnings), 0)

    def test_phase2_compatibility_and_solvers(self) -> None:
        from ctf_toolkit.blockchain.protocols import (
            compute_merkle_root,
            crack_keccak256_wordlist,
            resolve_4byte_selector,
        )
        from ctf_toolkit.crypto.auto_decode import auto_decode_layers
        from ctf_toolkit.crypto.hashes import crack_crc32_4byte
        from ctf_toolkit.crypto.rsa import rsa_factor_small
        from ctf_toolkit.forensics.linux_forensics import audit_etc_passwd, audit_sshd_config
        from ctf_toolkit.forensics.pdf import scan_pdf_raw_objects
        from ctf_toolkit.osint_misc.binary_formats import (
            decode_cbor_raw,
            decode_msgpack_raw,
            decode_protobuf_raw,
            decode_timestamp_delta_channel,
            decompress_git_loose_object,
            parse_asn1_der_strings,
            parse_bplist_strings,
            reassemble_seq_chunks,
        )
        from ctf_toolkit.osint_misc.config_hunter import (
             extract_xml_namespaced_values,
            parse_jsonc,
            parse_mime_email_parts,
            parse_toml_secrets,
            resolve_json_pointer,
        )
        from ctf_toolkit.osint_misc.esolang import befunge_extract_strings, decode_collatz_ascii
        from ctf_toolkit.osint_misc.profile_miner import mine_profile_handles
        from ctf_toolkit.osint_misc.stego import (
            decode_case_bitstream,
            decode_seven_segment,
            decode_unicode_tag_plane,
            extract_acrostic,
            extract_periodic_step,
            reconstruct_from_regex_pattern,
        )
        from ctf_toolkit.reversing.stack_strings import extract_mov_stack_strings
        from ctf_toolkit.reversing.transforms import solve_crackme_byte_transform
        from ctf_toolkit.utils.encodings import decode_base64_payload

        # RSA small factor
        p, q, e = 101, 1031, 17
        n = p * q
        m = 42
        c = pow(m, e, n)
        self.assertEqual(rsa_factor_small(n, e), (101, 1031))
        self.assertEqual(int.from_bytes(rsa_factor_small(n, e, c), "big"), m)

        # CRC32 4-byte algebraic inversion
        target_crc = zlib.crc32(b"FLAG") & 0xFFFFFFFF
        self.assertEqual(crack_crc32_4byte(target_crc), "FLAG")

        # PDF raw object scan & Base64 payload
        self.assertIn("GETSFLAG{pdf_tok}", scan_pdf_raw_objects(b"%PDF-1.4 (GETSFLAG{pdf_tok}) Tj"))
        self.assertEqual(decode_base64_payload("R0VUU0ZMQUd7YjY0fQ=="), b"GETSFLAG{b64}")
        self.assertEqual(auto_decode_layers("5230565555305a4d51556437596a593066513d3d"), b"GETSFLAG{b64}")

        # Profile miner & stack strings
        prof = mine_profile_handles("Contact @night_fox at fox@example.com with GETSFLAG{osint_ok}")
        self.assertIn("@night_fox", prof["handles"])
        self.assertIn("GETSFLAG{osint_ok}", prof["flags"])
        self.assertIn("GETS", extract_mov_stack_strings("mov DWORD PTR [rbp-4], 0x53544547"))

        # Stego helpers
        tag_str = "".join(chr(0xE0000 + ord(ch)) for ch in "FLAG{tag}")
        self.assertEqual(decode_unicode_tag_plane(tag_str), "FLAG{tag}")
        self.assertEqual(decode_seven_segment("abcdef bc abdeg"), "012")
        self.assertEqual(extract_acrostic("First\nLine\nAcrostic\nGoal"), "FLAG")
        self.assertEqual(extract_periodic_step("GxxxxExxxxTxxxxS", step=5), "GETS")
        self.assertEqual(decode_case_bitstream("aBcDeFgH"), bytes([0b01010101]))
        self.assertEqual(reconstruct_from_regex_pattern(r"^GETSFLAG\{[a][b][c]\}$"), "GETSFLAG{abc}")

        # Esolang & Collatz
        self.assertEqual(befunge_extract_strings('"}galF{" >:#,_@'), "{Flag}")
        self.assertEqual(decode_collatz_ascii([1], offset=65), "A")

        # Binary wire formats
        self.assertEqual(decode_msgpack_raw(b"\xa4FLAG"), "FLAG")
        self.assertEqual(decode_cbor_raw(b"\x64FLAG"), "FLAG")
        self.assertEqual(decode_protobuf_raw(b"\x0a\x04FLAG"), {1: ["FLAG"]})
        self.assertEqual(parse_asn1_der_strings(b"\x30\x06\x04\x04FLAG"), [b"FLAG"])
        bplist_blob = plistlib.dumps({"secret": "GETSFLAG{plist}"}, fmt=plistlib.FMT_BINARY)
        self.assertIn("GETSFLAG{plist}", parse_bplist_strings(bplist_blob))
        git_blob = zlib.compress(b"blob 4\x00FLAG")
        self.assertEqual(decompress_git_loose_object(git_blob), b"FLAG")
        self.assertEqual(reassemble_seq_chunks([b"SEQ:2:AG}", b"SEQ:1:FL"]), b"FLAG}")
        self.assertEqual(decode_timestamp_delta_channel([1700000000 + 70, 1700000000 + 128 + 76]), "FL")

        # Config hunters
        self.assertEqual(parse_toml_secrets('flag = "GETSFLAG{toml}"')["parsed"]["flag"], "GETSFLAG{toml}")
        self.assertEqual(parse_jsonc('{\n// comment\n"a": 1,\n}')["a"], 1)
        self.assertEqual(resolve_json_pointer({"a": {"b": ["x", "y"]}}, "/a/b/1"), "y")
        eml = b"From: a@b.com\r\nX-Flag: GETSFLAG{eml}\r\n\r\nBody text"
        self.assertEqual(parse_mime_email_parts(eml)["headers"]["X-Flag"], "GETSFLAG{eml}")
        self.assertIn("GETSFLAG{xml}", extract_xml_namespaced_values('<ns:root xmlns:ns="urn:x"><ns:item>GETSFLAG{xml}</ns:item></ns:root>'))

        # Linux forensics & crackme transform
        self.assertEqual(len(audit_etc_passwd("hacker:x:0:0:root:/root:/bin/bash")), 1)
        self.assertEqual(len(audit_sshd_config("PermitRootLogin yes")), 1)
        enc_flag = bytes(b ^ 0x5A for b in b"GETSFLAG{xor_test}")
        self.assertTrue(any(pt == b"GETSFLAG{xor_test}" for _, pt in solve_crackme_byte_transform(enc_flag)))

        # Blockchain helpers
        root_hex = compute_merkle_root(["a", "b"])
        self.assertTrue(root_hex.startswith("0x") and len(root_hex) == 66)
        self.assertEqual(resolve_4byte_selector("0xa9059cbb", ["transfer(address,uint256)"]), "transfer(address,uint256)")
        from ctf_toolkit.blockchain.protocols import _keccak256
        h_word = _keccak256(b"secret_pass").hex()
        self.assertEqual(crack_keccak256_wordlist(h_word, ["wrong", "secret_pass"]), "secret_pass")

    def test_phase3_external_2025_2026_solvers(self) -> None:
        from ctf_toolkit.crypto.block_attacks import cbc_bitflip_craft, ecb_byte_at_a_time_recover
        from ctf_toolkit.crypto.ecc import ecc_point_add, ecc_scalar_mul, ecc_small_subgroup_dlog, ecc_smarts_attack
        from ctf_toolkit.crypto.lattice_lll import gauss_reduce_2d, lll_reduce
        from ctf_toolkit.crypto.rsa_auto import parse_pem_key, solve_rsa_auto
        from ctf_toolkit.forensics.carver import carve_embedded_files
        from ctf_toolkit.forensics.wasm_analyzer import analyze_wasm_binary
        from ctf_toolkit.web.deserialization import (
            build_php_serialized_object,
            parse_php_serialized,
            pickle_inspect_opcodes,
        )
        from ctf_toolkit.web.jwt_attacks import (
            jwt_crack_hs256,
            jwt_forge_key_confusion,
            jwt_forge_none,
            jwt_sign_hs256,
        )

        # PEM parser & Auto-RSA
        rsa_key = RSA.generate(1024)
        pem_info = parse_pem_key(rsa_key.publickey().export_key())
        self.assertEqual(pem_info["n"], rsa_key.n)
        pt_int = int.from_bytes(b"FLAG{rsa_auto}", "big")
        res_auto = solve_rsa_auto(n=rsa_key.n, e=3, c=pt_int**3)
        self.assertEqual(res_auto["plaintext"], b"FLAG{rsa_auto}")

        # Lattice LLL
        reduced = lll_reduce([[1, 1, 1], [-1, 0, 2], [3, 5, 6]])
        self.assertEqual(len(reduced), 3)
        u, v = gauss_reduce_2d([10, 1], [9, 1])
        self.assertLessEqual(sum(x * x for x in u), 5)

        # ECC arithmetic & BSGS & Smart's attack on anomalous curve mod p=43 (y^2 = x^3 + 26x + 41 mod 43 has #E=43)
        p = 43
        a, b = 26, 41
        G = (2, 12)
        Q = ecc_scalar_mul(19, G, a, p)
        self.assertIsNotNone(Q)
        self.assertEqual(ecc_small_subgroup_dlog(G, Q, a, p, bound=100), 19)
        self.assertEqual(ecc_smarts_attack(G, Q, a, b, p), 19)

        # CBC Bitflip & ECB Oracle
        iv = b"\x00" * 16
        flipped = cbc_bitflip_craft(iv, b"admin=0;role=usr", b"admin=1;role=adm")
        self.assertEqual(bytes(x ^ y for x, y in zip(flipped, b"admin=0;role=usr")), b"admin=1;role=adm")

        from ctf_toolkit.crypto.aes import aes_ecb_encrypt
        secret_key = b"0123456789abcdef"
        secret_suffix = b"FLAG{ecb}"
        recovered = ecb_byte_at_a_time_recover(lambda prefix: aes_ecb_encrypt(prefix + secret_suffix, secret_key), max_bytes=16)
        self.assertTrue(recovered.startswith(b"FLAG{ecb}"))

        # JWT active attacks
        none_tok = jwt_forge_none({"admin": True})
        self.assertTrue(none_tok.endswith("."))
        hs_tok = jwt_sign_hs256({"user": "admin"}, "letmein")
        self.assertEqual(jwt_crack_hs256(hs_tok, ["wrong", "letmein"]), "letmein")
        kc_tok = jwt_forge_key_confusion({"admin": True}, b"-----BEGIN PUBLIC KEY-----")
        self.assertEqual(len(kc_tok.split(".")), 3)

        # Deserialization helpers
        pkl = pickle.dumps({"flag": "GETSFLAG{pkl}"})
        ops = pickle_inspect_opcodes(pkl)
        self.assertTrue(any(arg == "GETSFLAG{pkl}" for _, arg, _ in ops))
        php_s = build_php_serialized_object("User", {"role": "admin"}, bypass_wakeup=True)
        self.assertIn('O:4:"User":2:', php_s)
        self.assertEqual(parse_php_serialized(php_s)["classes"], ["User"])

        # Binary Carver & Wasm Dissector
        zlib_stream = zlib.compress(b"GETSFLAG{carved_zlib_stream}")
        blob = b"PADDING_HEADER" * 4 + zlib_stream
        carved = carve_embedded_files(blob)
        self.assertTrue(any(c["decompressed"] == b"GETSFLAG{carved_zlib_stream}" for c in carved))

        # Minimal valid .wasm with Export "check_flag" and Data "GETSFLAG{wasm}"
        wasm_blob = (
            b"\x00asm\x01\x00\x00\x00"
            + b"\x07\x0e\x01\x0a" + b"check_flag" + b"\x00\x00"
            + b"\x0b\x14\x01\x00\x41\x00\x0b\x0e" + b"GETSFLAG{wasm}"
        )
        wasm_info = analyze_wasm_binary(wasm_blob)
        self.assertIn("check_flag", wasm_info["exports"])
        self.assertIn("GETSFLAG{wasm}", wasm_info["data_strings"])

    def test_ctf_solutions_md_1600_completeness(self) -> None:
        sol_path = Path(__file__).resolve().parents[3] / "CTF-Vault" / "CTF_SOLUTIONS.md"
        if not sol_path.exists():
            return
        text = sol_path.read_text(encoding="utf-8", errors="replace")
        blocks = re.split(r"(?=^### )", text, flags=re.MULTILINE)[1:]
        self.assertEqual(len(blocks), 1600)
        for idx, b in enumerate(blocks, 1):
            self.assertIn("```", b, f"Block #{idx} missing code block")
            self.assertTrue(
                any(k in b for k in ("Toolkit Abstraction", "Abstraction Candidate", "Toolkit Integration")),
                f"Block #{idx} missing Toolkit Abstraction",
            )
            self.assertIsNotNone(
                re.search(r"(?:GETSFLAG|CTF|FLAG|CT)\{[^}\n]+\}", b, re.IGNORECASE),
                f"Block #{idx} missing captured flag",
            )


def test_all_python_files_compile_cleanly() -> None:
    TestV4AuditRemediation().test_all_python_files_compile_cleanly()


def test_command_palette_indexes_over_500_functions() -> None:
    TestV4AuditRemediation().test_command_palette_indexes_over_500_functions()


def test_des_no_deprecation_warning() -> None:
    TestV4AuditRemediation().test_des_no_deprecation_warning()


def test_phase2_compatibility_and_solvers() -> None:
    TestV4AuditRemediation().test_phase2_compatibility_and_solvers()


def test_phase3_external_2025_2026_solvers() -> None:
    TestV4AuditRemediation().test_phase3_external_2025_2026_solvers()


def test_ctf_solutions_md_1600_completeness() -> None:
    TestV4AuditRemediation().test_ctf_solutions_md_1600_completeness()


if __name__ == "__main__":
    unittest.main()
