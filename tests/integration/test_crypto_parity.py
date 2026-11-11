import unittest
from ctf_toolkit.crypto.dh_ecc_tool import diffie_hellman_compute, ecc_point_operation, is_point_on_curve
from ctf_toolkit.crypto.auto_solver import solve_crypto_task, extract_flag


class TestCryptoParity(unittest.TestCase):
    def test_diffie_hellman_known_private(self) -> None:
        p = 10007
        g = 5
        a = 1234
        b = 5678
        A = pow(g, a, p)
        B = pow(g, b, p)

        res_a = diffie_hellman_compute(p=p, g=g, a=a, B=B)
        res_b = diffie_hellman_compute(p=p, g=g, b=b, A=A)
        self.assertEqual(res_a["shared_secret"], res_b["shared_secret"])
        self.assertEqual(res_a["shared_secret"], pow(g, a * b, p))

    def test_diffie_hellman_discrete_log(self) -> None:
        p = 10007
        g = 5
        a = 42
        b = 1337
        A = pow(g, a, p)
        B = pow(g, b, p)

        res = diffie_hellman_compute(p=p, g=g, A=A, B=B)
        self.assertEqual(res["a"], a)
        self.assertEqual(res["shared_secret"], pow(g, a * b, p))

    def test_ecc_point_addition_and_multiplication(self) -> None:
        # Curve: y^2 = x^3 + 2x + 3 (mod 97)
        a, b, p = 2, 3, 97
        P = (3, 6)
        self.assertTrue(is_point_on_curve(P, a, b, p))

        # Test scalar mul 2*P
        res_mul = ecc_point_operation("mul", a, b, p, Px=3, Py=6, k=2)
        self.assertFalse(res_mul["is_infinity"])
        Rx = int(str(res_mul["Rx"]))
        Ry = int(str(res_mul["Ry"]))
        self.assertTrue(is_point_on_curve((Rx, Ry), a, b, p))

        # Test point add P + P == 2*P
        res_add = ecc_point_operation("add", a, b, p, Px=3, Py=6, Qx=3, Qy=6)
        self.assertEqual(res_add["Rx"], Rx)
        self.assertEqual(res_add["Ry"], Ry)

    def test_solve_crypto_task_dh_prompt(self) -> None:
        prompt = "DH Params: p = 10007, g = 5, a = 42, B = 2000"
        res = solve_crypto_task(prompt)
        # Should not crash and execute clean heuristics
        self.assertTrue(res is None or isinstance(res, str))

    def test_solve_crypto_task_rsa_d_leak(self) -> None:
        n = 8299031137761985917024815727382322302024892464484873799991314659381305622825816292799414792523475518636151190762581325962743220701545790700035216592121157218145582904619827585880207
        e = 65537
        m_bytes = b"GETSFLAG{rsa_d_leak_recovered}"
        m = int.from_bytes(m_bytes, "big")
        c = pow(m, e, n)
        # Compute d via phi
        phi = 8299031137761985917024815727382322302024892464484873799991314659381305622825816292799414786412367589632692931957244260734608737547140609702226464683699809155001683614609709035687896
        from ctf_toolkit.utils.math import modinv
        d = modinv(e, phi)

        desc = f"RSA with private exponent:\nn = {n}\nd = {d}\nc = {c}"
        flag = solve_crypto_task(desc)
        self.assertEqual(flag, "GETSFLAG{rsa_d_leak_recovered}")


def test_crypto_parity_suite() -> None:
    suite = unittest.TestLoader().loadTestsFromTestCase(TestCryptoParity)
    res = unittest.TextTestRunner(verbosity=1).run(suite)
    assert res.wasSuccessful(), "Crypto parity test suite failed"


if __name__ == "__main__":
    unittest.main()
