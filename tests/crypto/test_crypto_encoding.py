from ctf_toolkit.crypto.encoding import (
    ascii85_decode,
    base32_decode_autopad,
    base85_decode,
    binary_to_text,
    decimal_to_text,
    rot13,
    smart_decode,
)


def test_base32_decode_autopad():
    assert base32_decode_autopad("JBSWY3DPEBLW64TMMQ======") == b"Hello World"
    assert base32_decode_autopad("JBSWY3DPEBLW64TMMQ") == b"Hello World"


def test_rot13():
    assert rot13("hello") == "uryyb"
    assert rot13("uryyb") == "hello"


def test_smart_decode():
    res = smart_decode("R0VUU0ZMQUd7dGVzdH0=")
    assert res.get("base64") == "GETSFLAG{test}"


def test_binary_to_text():
    binary = "01000001 01000010 01000011"
    assert binary_to_text(binary) == "ABC"


def test_decimal_to_text():
    decimal_str = "65 66 67"
    assert decimal_to_text(decimal_str) == "ABC"


def test_ascii85_decode():
    assert ascii85_decode("87cURDZ") == b"Hello"


def test_base85_decode():
    assert base85_decode("NM&qnZv") == b"Hello"
