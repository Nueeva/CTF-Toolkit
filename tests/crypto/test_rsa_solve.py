from ctf_toolkit.crypto.rsa import rsa_solve_pqec


def test_rsa_solve_pqec():
    p = 61
    q = 53
    e = 17
    # Message: 65 ('A')
    # c = 65^17 mod (61*53) = 65^17 mod 3233
    n = p * q
    c = pow(65, e, n)
    decrypted_bytes = rsa_solve_pqec(p, q, e, c)
    assert decrypted_bytes == b"A"
