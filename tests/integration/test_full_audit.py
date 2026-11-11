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


def test_full_audit_enhancements_suite() -> None:
    suite = unittest.TestLoader().loadTestsFromTestCase(TestFullAuditEnhancements)
    res = unittest.TextTestRunner(verbosity=1).run(suite)
    assert res.wasSuccessful(), "Full audit enhancements suite failed"


if __name__ == "__main__":
    unittest.main()
