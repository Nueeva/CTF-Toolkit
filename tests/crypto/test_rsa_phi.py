from ctf_toolkit.crypto.rsa import rsa_solve_phi_e_c


def test_rsa_solve_phi_e_c():
    p = 61
    q = 53
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 17
    c = pow(65, e, n)

    dec = rsa_solve_phi_e_c(n, phi, e, c)
    assert dec == b"A"

