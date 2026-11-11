import unittest
from ctf_toolkit.utils.ctfd_client import CTFdClient
from ctf_toolkit.utils.ctf_auto_solver import extract_flag, solve_challenge_text


class TestCTFdAutoTrain(unittest.TestCase):
    def test_extract_flag_formats(self) -> None:
        self.assertEqual(extract_flag("flag is GETSFLAG{test_123}"), "GETSFLAG{test_123}")
        self.assertEqual(extract_flag("here: CTF{classical_cipher}"), "CTF{classical_cipher}")
        self.assertEqual(extract_flag("found picoCTF{flag_456}"), "picoCTF{flag_456}")
        self.assertEqual(extract_flag("secret CT{morse_flag}"), "CT{morse_flag}")

    def test_solve_challenge_text_rsa(self) -> None:
        p = 2037035976334486086268445688409378161051468393665936250636140449354381299763336706183397533
        q = 4074071952668972172536891376818756322102936787331872501272280898708762599526673412366794779
        e = 65537
        m = int.from_bytes(b"GETSFLAG{rsa_test}", "big")
        c = pow(m, e, p * q)
        desc = f"p = {p}\nq = {q}\ne = {e}\nc = {c}\nFind the flag!"
        recovered = solve_challenge_text(desc)
        self.assertEqual(recovered, "GETSFLAG{rsa_test}")

    def test_solve_challenge_text_b64(self) -> None:
        desc = "Decode this payload:\n```\nR0VUU0ZMQUd7YjY0X2RlY29kZXJ9\n```"
        recovered = solve_challenge_text(desc)
        self.assertEqual(recovered, "GETSFLAG{b64_decoder}")

    def test_ctfd_client_instantiation(self) -> None:
        client = CTFdClient(base_url="https://getsflag.com")
        self.assertEqual(client.base_url, "https://getsflag.com")
        self.assertFalse(client.logged_in)

    def test_blockchain_eip55_and_units(self) -> None:
        from ctf_toolkit.blockchain.protocols import to_checksum_address, is_checksum_address, convert_eth_unit
        raw = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
        expected = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        self.assertEqual(to_checksum_address(raw), expected)
        self.assertTrue(is_checksum_address(expected))
        self.assertFalse(is_checksum_address(raw))
        # 1 ether = 10^18 wei = 10^9 gwei
        self.assertEqual(convert_eth_unit(1, "ether", "wei"), "1000000000000000000")
        self.assertEqual(convert_eth_unit("1000000000", "gwei", "ether"), "1")

    def test_web_cheatsheet_registry(self) -> None:
        from ctf_toolkit.web.cheatsheets import get_web_cheatsheet, format_cheatsheet_text
        sqli = get_web_cheatsheet("SQLi")
        self.assertIn("SQLi", sqli)
        self.assertTrue(len(sqli["SQLi"]) >= 5)
        formatted = format_cheatsheet_text("LFI")
        self.assertIn("etc/passwd", formatted)


def test_ctfd_auto_train_suite() -> None:
    suite = unittest.TestLoader().loadTestsFromTestCase(TestCTFdAutoTrain)
    res = unittest.TextTestRunner(verbosity=1).run(suite)
    assert res.wasSuccessful(), "CTFd client & auto solver tests failed"


if __name__ == "__main__":
    unittest.main()
