import os
import tempfile

from ctf_toolkit.crypto import mathutil
from ctf_toolkit.crypto.ast_tracer import (
    extract_bytes_constants,
    extract_numeric_blobs,
    infer_params,
    plan_from,
    trace_directory,
    trace_source,
)


def test_iroot_is_exact_and_fast():
    assert mathutil.iroot(10 ** 24, 3) == (10 ** 8, True)
    root, exact = mathutil.iroot(10 ** 24 + 1, 3)
    assert root == 10 ** 8 and exact is False


def test_fermat_recovers_close_primes():
    p = 1000003
    q = 1000033
    assert mathutil.fermat_factor(p * q) == (p, q)


def test_pollard_pm1_recovers_smooth_prime():
    # p-1 is fully smooth, so p-1 method must find it immediately
    p = 65537
    q = 1000003
    found = mathutil.pollard_pm1(p * q, bound=10_000)
    assert found in (p, q)


def test_wiener_recovers_small_d():
    p, q = 1000003, 1000033
    n = p * q
    phi = (p - 1) * (q - 1)
    d = 5
    e = pow(d, -1, phi)
    assert mathutil.wiener_attack(e, n) == d


def test_tracer_binds_roles_despite_obfuscated_names():
    src = (
        "from Crypto.Util.number import getPrime, bytes_to_long\n"
        "zz = getPrime(64)\nqq = getPrime(64)\nnn = zz * qq\nee = 65537\n"
        "cc = pow(bytes_to_long(flag), ee, nn)\nprint(nn, ee, cc)\n"
    )
    trace = trace_source(src)
    assert trace.primary == "rsa"
    # n is discovered from the zz*qq product even though the variable is `nn`
    assert trace.roles.get("n") == "nn"
    assert trace.roles.get("e") == "ee"
    assert trace.roles.get("c") == "cc"


def test_tracer_reads_literal_exponent_from_pow():
    src = "c = pow(m, 3, n)\n"
    trace = trace_source(src)
    assert trace.params.get("e") == 3
    assert "rsa_small_e_root" in trace.attack_plan


def test_tracer_detects_aes_mode_and_key_constant():
    src = (
        "from Crypto.Cipher import AES\n"
        "key = bytes(range(16))\n"
        "iv = bytes(range(16, 32))\n"
        "ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg, 16))\n"
    )
    trace = trace_source(src)
    assert trace.primary == "aes"
    assert "aes-CBC" in trace.encodings
    consts = extract_bytes_constants(src)
    assert any(len(b) == 16 for _n, b in consts)


def test_tracer_survives_python2_source():
    src = "print 'hello'\nc = pow(m, e, n)\n"
    trace = trace_source(src)
    assert trace.parse_error is not None
    assert trace.categories


def test_numeric_blobs_classifies_by_label_and_magnitude():
    text = "n = 123456789012345678901234567890\ne = 65537\n"
    blobs = extract_numeric_blobs(text)
    labels = {b.label for b in blobs}
    assert labels == {"n", "e"}
    assert blobs[0].value > blobs[1].value


def test_infer_params_uses_labels_before_magnitude():
    trace = trace_source("def f(p,q):\n    n = p*q\n    return pow(m, e, n)\n")
    out = "modulus_like = 3233\nother = 17\n"
    res = infer_params(trace, out)
    # No usable labels, so magnitude fallback assigns n and c
    assert "n" in res["params"]


def test_infer_params_rejects_c_larger_than_n():
    trace = trace_source("c = pow(m, e, n)\n")
    huge = 10 ** 200
    out = f"n = {10 ** 100}\ne = 65537\nc = {huge}\nd = {10 ** 99}\n"
    res = infer_params(trace, out)
    assert res["params"]["c"] < res["params"]["n"]


def test_plan_omits_unmet_attacks():
    trace = trace_source("c = pow(m, e, n)\n")
    plan = plan_from(trace, {"n": 3233})
    assert "rsa_given_factors" not in plan
    assert "rsa_fermat" in plan


def test_plan_has_given_factors_when_present():
    trace = trace_source("c = pow(m, e, n)\n")
    plan = plan_from(trace, {"n": 3233, "p": 61, "q": 53, "e": 17, "c": 3})
    assert plan[0] == "rsa_given_factors"


def test_trace_directory_picks_chall_and_output():
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "chall.py"), "w") as fh:
            fh.write("n = 3233\nc = pow(m, e, n)\n")
        with open(os.path.join(tmp, "output.txt"), "w") as fh:
            fh.write("n = 3233\ne = 17\nc = 1234\n")
        report = trace_directory(tmp)
        assert report["script"] == "chall.py"
        assert report["output_file"] == "output.txt"
        assert report["params"]["n"] == 3233
