import unittest
from ctf_toolkit.crypto.cipher_id import identify_cipher_text, identify_hash_format
from ctf_toolkit.utils.flag_manager import IntelligentFlagManager


class TestFullAuditEnhancements(unittest.TestCase):
    def test_identify_hash_formats(self) -> None:
        md5_res = identify_hash_format("5f4dcc3b5aa765d61d8327deb882cf99")
        self.assertTrue(any(h["algorithm"] == "MD5" for h in md5_res))

        sha256_res = identify_hash_format("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertTrue(any("SHA-256" in h["algorithm"] for h in sha256_res))

        bcrypt_res = identify_hash_format("$2b$12$e868d4a4d6...dummy")
        self.assertTrue(any(h["algorithm"] == "Bcrypt" for h in bcrypt_res))

    def test_identify_cipher_text_characteristics(self) -> None:
        b64_info = identify_cipher_text("Uml2YSBpcyBoZXJlIQ==")
        self.assertIn("Base64", b64_info["likely_types"])

        morse_info = identify_cipher_text("... --- ...")
        self.assertIn("Morse Code", morse_info["likely_types"])

        a1z26_info = identify_cipher_text("3-20-6-1-12-19")
        self.assertIn("A1Z26 / Number Positional", a1z26_info["likely_types"])

    def test_custom_flag_manager_lifecycle(self) -> None:
        import tempfile
        from pathlib import Path
        tmp_cfg = Path(tempfile.gettempdir()) / "test_flag_cfg.json"
        if tmp_cfg.exists():
            tmp_cfg.unlink()

        fm = IntelligentFlagManager(config_path=tmp_cfg)
        self.assertTrue(len(fm.templates) >= 8)

        # Add custom flag format
        fm.add_template("NUEVA_CTF", r"NUEVA\{[^}\n]+\}", priority=120)
        sample = "Here is the flag: NUEVA{state_of_the_art_toolkit} and picoCTF{old_one}"
        flags = fm.extract_flags(sample)
        self.assertEqual(len(flags), 2)
        # NUEVA should come first because priority=120 > picoCTF priority=95
        self.assertEqual(flags[0]["template"], "NUEVA_CTF")
        self.assertEqual(flags[0]["flag"], "NUEVA{state_of_the_art_toolkit}")

        # Remove custom format
        fm.remove_template("NUEVA_CTF")
        self.assertIsNone(fm.find_first_flag("NUEVA{state_of_the_art_toolkit}"))


    # Test dynamic writeup & python solver generation
    def test_writeup_and_solver_generation(self) -> None:
        from ctf_toolkit.utils.writeup_generator import DynamicWriteupGenerator
        import tempfile
        from pathlib import Path
        tmp_dir = Path(tempfile.gettempdir()) / "ctf_wu_test"
        steps = [
            {"title": "Triage", "desc": "Checked RSA params", "cmd": "python main.py identify ..."},
            {"title": "Decrypt", "desc": "Solved using RSA math", "python_code": "val = 42\nprint(val)"},
        ]
        wf, sf = DynamicWriteupGenerator.generate_writeup_and_solver(
            "TestChallenge", "Crypto", "LKSJAKTIM{writeup_ready}", steps, output_dir=tmp_dir, points=150
        )
        self.assertTrue(wf.exists())
        self.assertTrue(sf.exists())
        self.assertIn("LKSJAKTIM{writeup_ready}", wf.read_text(encoding="utf-8"))
        self.assertIn("val = 42", sf.read_text(encoding="utf-8"))

    # Test AutoTriageDispatcher
    def test_auto_triage_dispatcher_formats(self) -> None:
        from ctf_toolkit.triage.dispatcher import AutoTriageDispatcher
        import tempfile
        from pathlib import Path
        # Test synthetic PNG
        png_file = Path(tempfile.gettempdir()) / "test_art.png"
        png_file.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"GETSFLAG{png_magic_test}")
        res_png = AutoTriageDispatcher.dispatch_file(png_file)
        self.assertIn("PNG_Specialist", res_png["dispatched_specialists"])
        self.assertIn("GETSFLAG{png_magic_test}", res_png["flags_found"])

        # Test synthetic ZIP
        import zipfile
        zip_file = Path(tempfile.gettempdir()) / "test_art.zip"
        with zipfile.ZipFile(zip_file, "w") as zf:
            zf.writestr("secret.txt", "Flag: academy{zip_dispatcher_ok}")
        res_zip = AutoTriageDispatcher.dispatch_file(zip_file)
        self.assertIn("Archive_Specialist", res_zip["dispatched_specialists"])
        self.assertIn("academy{zip_dispatcher_ok}", res_zip["flags_found"])

def test_full_audit_enhancements_suite() -> None:
    suite = unittest.TestLoader().loadTestsFromTestCase(TestFullAuditEnhancements)
    res = unittest.TextTestRunner(verbosity=1).run(suite)
    assert res.wasSuccessful(), "Full audit enhancements suite failed"


if __name__ == "__main__":
    unittest.main()
