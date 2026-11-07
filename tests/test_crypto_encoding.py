from ctf_toolkit.crypto.encoding import base32_decode_autopad, rot13, smart_decode


def test_base32_decode_autopad():
    assert base32_decode_autopad("JBSWY3DPEBLW64TMMQ======") == b"Hello World"
    # Test without padding
    assert base32_decode_autopad("JBSWY3DPEBLW64TMMQ") == b"Hello World"


def test_rot13():
    assert rot13("hello") == "uryyb"
    assert rot13("uryyb") == "hello"


def test_smart_decode():
    res = smart_decode("R0VUU0ZMQUd7dGVzdH0=")
    assert res.get("base64") == "GETSFLAG{test}"
