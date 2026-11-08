from __future__ import annotations

import io
from pathlib import Path
import struct
import unittest
from PIL import Image

from ctf_toolkit.crypto.auto_decode import auto_decode_layers
from ctf_toolkit.crypto.classical import (
    base58_ripple_decode,
    spiral_route_decrypt,
    variant_beaufort_decrypt,
)
from ctf_toolkit.crypto.ecc import ecc_smarts_attack
from ctf_toolkit.crypto.encoding import (
    ascii85_decode,
    base_n_decode,
    xxdecode,
)
from ctf_toolkit.crypto.prng import glibc_rand_generate, glibc_rand_predict
from ctf_toolkit.crypto.rsa import factor_integer_auto, solve_rsa_auto
from ctf_toolkit.forensics.apk_tools import extract_dex_strings, inspect_apk_components
from ctf_toolkit.forensics.image_channels import extract_channel_lsb, find_flags_in_channel
from ctf_toolkit.forensics.linux_forensics import decrypt_marker_bounded_xor
from ctf_toolkit.forensics.log_hunter import detect_line_incident
from ctf_toolkit.forensics.network_artifacts import extract_dns_base32_subdomains
from ctf_toolkit.forensics.pcap_extract import decrypt_pcap_tls_keylog, repair_pcap_header
from ctf_toolkit.forensics.pyc_decompile import extract_pyc_constants_raw
from ctf_toolkit.osint_misc.esolang import ook_to_brainfuck
from ctf_toolkit.osint_misc.osint_helpers import lookup_city_by_coordinates
from ctf_toolkit.osint_misc.uudecode import encode_uu, encode_xx
from ctf_toolkit.reversing.permutations_and_asm import (
    apply_permutation,
    emulate_x86_snippet,
    invert_permutation,
    permute_bits_in_byte,
)
from ctf_toolkit.triage.analyzer import triage_data
from ctf_toolkit.ui.magic_solver import solve_magic
from ctf_toolkit.ui.palette import build_tool_catalog
from ctf_toolkit.utils.encodings import decode_base64_payload
from ctf_toolkit.utils.text import extract_all_strings, extract_utf16_strings, resistor_colors_to_int
from ctf_toolkit.web.helpers import build_cors_request
from ctf_toolkit.web.logic import scan_mass_assignment_text
from ctf_toolkit.web.robots import parse_robots_txt


class TestFindingsRemediation(unittest.TestCase):
    def test_f04_city_coordinates_kodiak_and_world(self):
        # F-04: Kodiak Alaska (57.79, -152.407) was 0/12 in picoCTF Mr-Worldwide
        city = lookup_city_by_coordinates(57.79, -152.407)
        self.assertIn("kodiak", city.lower())

        # Paris and Tokyo
        self.assertIn("paris", lookup_city_by_coordinates(48.8566, 2.3522).lower())
        self.assertIn("tokyo", lookup_city_by_coordinates(35.6762, 139.6503).lower())

    def test_f05_magic_solver_caesar_wrapped_flag(self):
        # F-05: input with encrypted Caesar inside flag wrapper should not halt prematurely
        encrypted_input = b"picoCTF{dspttjohuifsvcjdpoabrkttds}"
        best_data, path, score, history = solve_magic(encrypted_input)
        self.assertIn(b"crossingtherubiconzaqjsscr", best_data)

    def test_f06_f22_triage_apk_dex_and_zero_width_guard(self):
        # F-06 / F-22: Triage on DEX/APK must not report bogus Zero-Width
        dex_header = b"dex\n035\x00" + b"\x00" * 100
        rep = triage_data(dex_header)
        self.assertIn("DEX", rep.magic_type)
        self.assertNotIn("Zero-Width Steganography", rep.encodings_detected)

    def test_f07_rsa_integer_factor_auto(self):
        # F-07: picoCTF john_pollard modulus (53-bit)
        n = 4966306421059967
        factors, strategy = factor_integer_auto(n)
        self.assertIsNotNone(factors)
        self.assertEqual(len(factors), 2)
        p, q = factors
        self.assertEqual(p * q, n)
        self.assertIn(p, (67867967, 73176001))
        self.assertEqual(strategy, "fermat")

    def test_f09_utf16_string_extraction(self):
        # F-09: extract_utf16_strings & extract_all_strings
        flag = "FLAG{utf16_extraction_test}"
        blob = b"\x00\x00" + flag.encode("utf-16le") + b"\xff\xff" + flag.encode("utf-16be")
        utf16_hits = extract_utf16_strings(blob, min_len=4)
        self.assertIn(flag, utf16_hits)
        all_hits = extract_all_strings(blob, min_len=4)
        self.assertIn(flag, all_hits)

    def test_f10_mass_assignment_request_get_json(self):
        # F-10: scanner recognizing request.get_json()
        findings = scan_mass_assignment_text("user = User(**request.get_json())")
        self.assertTrue(len(findings) >= 1)
        self.assertEqual(findings[0]["reason"], "unpacked request payload")

    def test_f11_auto_decode_layers_rot13(self):
        # F-11: auto_decode_layers peel ROT13
        encoded = "SYNT{ebg13_ynlre_crryrq}"
        result = auto_decode_layers(encoded)
        self.assertEqual(result, b"FLAG{rot13_layer_peeled}")

    def test_f12_ecc_smarts_attack_graceful_fallback(self):
        # F-12: Smart's attack on non-invertible slopes must not crash
        res = ecc_smarts_attack((1, 21), (1, 250), 1, 168, 271)
        self.assertTrue(res is None or isinstance(res, int))

    def test_f13_dns_base32_subdomains_padding(self):
        # F-13: extract_dns_base32_subdomains with '=' padding
        raw_pcap_simulation = b"MIZTEIDTOVRGI33N.exfil-c2.net MFUW4IDEMF2GC===.exfil-c2.net"
        extracted = extract_dns_base32_subdomains(raw_pcap_simulation, "exfil-c2.net")
        self.assertEqual(extracted, b"b32 subdomain data")

    def test_f14_decode_base64_embedded_payload(self):
        # F-14: decode_base64_payload on embedded payload
        payload = b"\xff\xfe aGVsbG8= \x00"
        decoded = decode_base64_payload(payload)
        self.assertEqual(decoded, b"hello")

    def test_f15_pyc_constants_raw_preserves_braces(self):
        # F-15: extract_pyc_constants_raw preserves flag with braces
        simulated_pyc = b"\x00\x00\x00\x00GETSFLAG{pyc_shard7_ok}\x00\x00"
        constants = extract_pyc_constants_raw(simulated_pyc)
        self.assertIn("GETSFLAG{pyc_shard7_ok}", constants)

    def test_f16_base58_ripple_decode_leading_r(self):
        # F-16: leading 'r' zeroes in Ripple Base58
        self.assertEqual(base58_ripple_decode(""), b"")
        self.assertEqual(base58_ripple_decode("rrZ5U2"), b"\x00\x00abc")

    def test_f17_base_n_decode_alphabetic(self):
        # F-17: base_n_decode pure alphabetic string base <= 26
        self.assertEqual(base_n_decode("ba", 26), b"\x1a")

    def test_f18_ascii85_adobe_framing_and_xxdecode(self):
        # F-18: Adobe Ascii85 framing <~ ... ~>
        raw = b"hello world"
        adobe = b"<~BOu!rD]j7BEbo7~>"
        self.assertEqual(ascii85_decode(adobe), raw)

        # xxencode / xxdecode roundtrip
        encoded_xx = encode_xx(b"test", "data.txt")
        self.assertEqual(xxdecode(encoded_xx), b"test")

    def test_f19_ook_spec_alignment(self):
        # F-19: ook_to_brainfuck standard mapping
        self.assertEqual(ook_to_brainfuck("Ook. Ook."), "+")
        self.assertEqual(ook_to_brainfuck("Ook! Ook!"), "-")
        self.assertEqual(ook_to_brainfuck("Ook. Ook?"), ">")
        self.assertEqual(ook_to_brainfuck("Ook? Ook."), "<")

    def test_f20_encode_uu_mode_octal(self):
        # F-20: encode_uu default mode must be begin 644
        encoded = encode_uu(b"hello", "data.txt")
        self.assertTrue(encoded.startswith("begin 644 data.txt"))

    def test_f21_palette_indexes_binex(self):
        # F-21: binex functions indexed in CommandPalette / build_tool_catalog
        catalog = build_tool_catalog(force_refresh=True)
        names = [f["name"] for f in catalog]
        self.assertIn("p32", names)
        self.assertIn("p64", names)
        self.assertIn("parse_elf", names)
        self.assertIn("scan_gadgets", names)

    def test_f23_permutations_and_asm(self):
        # F-23: generic permutation, bit permutation, and asm simulation
        data = b"ABCDEF"
        perm = [5, 4, 3, 2, 1, 0]
        inv = invert_permutation(perm)
        applied = apply_permutation(data, perm)
        self.assertEqual(applied, b"FEDCBA")
        self.assertEqual(apply_permutation(applied, inv), data)

        b = 0b10000001
        bit_perm = [7, 6, 5, 4, 3, 2, 1, 0]
        self.assertEqual(permute_bits_in_byte(b, bit_perm), b)

        asm_code = """
        mov eax, 10
        add eax, 5
        sub eax, 2
        """
        regs = emulate_x86_snippet(asm_code)
        self.assertEqual(regs["eax"], 13)

    def test_f24_f25_pcap_repair_and_keylog(self):
        # F-25: pcap repair
        truncated = b"PACKET_PAYLOAD_WITHOUT_HEADER"
        repaired = repair_pcap_header(truncated)
        self.assertIn(repaired[:4], (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1"))
        self.assertEqual(len(repaired), 24 + len(truncated))

        # F-24: TLS keylog parser
        keylog = "CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef aabbccddeeff\n"
        res = decrypt_pcap_tls_keylog(b"", keylog)
        self.assertEqual(res["keys_count"], 1)

    def test_f26_find_flags_in_channel_case_insensitive(self):
        # F-26: flag patterns should catch ictf{...}
        flag = b"ictf{imaginary_flag_channel}"
        im = Image.new("RGB", (len(flag), 1))
        im.putdata([(b, 128, 128) for b in flag])
        buf = io.BytesIO()
        im.save(buf, format="PNG")
        flags = find_flags_in_channel(buf.getvalue(), "R")
        self.assertIn("ictf{imaginary_flag_channel}", flags)

    def test_f27_prng_glibc_rand_predict(self):
        # F-27: glibc rand generation and prediction
        outputs = glibc_rand_generate(seed=42, count=40)
        self.assertEqual(len(outputs), 40)
        predicted = glibc_rand_predict(outputs[:31], count=9)
        self.assertEqual(len(predicted), 9)

    def test_notes_robots_cors_and_resistor(self):
        # robots.py includes user-agents
        robots = "User-agent: Googlebot\nDisallow: /admin\nAllow: /public\n"
        parsed = parse_robots_txt(robots)
        self.assertIn("user-agents", parsed)
        self.assertEqual(parsed["user-agents"], ["Googlebot"])

        # web/helpers.py includes url in CORS request
        cors = build_cors_request("https://target.com")
        self.assertEqual(cors["url"], "https://target.com")

        # resistor_colors_to_int with multiplier
        val_direct = resistor_colors_to_int(["black", "violet", "black"])
        self.assertEqual(val_direct, 70)
        val_mult = resistor_colors_to_int(["yellow", "violet", "red"], multiplier=True)
        self.assertEqual(val_mult, 4700)

        # log_hunter detects URL-encoded SQLi
        line = '1.2.3.4 - - [08/Nov/2026:12:00:00 +0000] "GET /index.php?id=1%20union%20select%201 HTTP/1.1" 200 123'
        inc = detect_line_incident(line)
        self.assertIsNotNone(inc)
        self.assertEqual(inc.attack_type, "SQL Injection")


if __name__ == "__main__":
    unittest.main()
