from ctf_toolkit.crypto.encoding import quoted_printable_decode, smart_decode


def test_qp_known_vector() -> None:
    encoded = "GETSFLAG{quoted_printable_mail}=3D=3D=FFend"
    decoded = quoted_printable_decode(encoded)
    assert b"GETSFLAG{quoted_printable_mail}==" in decoded


def test_qp_soft_linebreaks() -> None:
    encoded = "Hello =\nWorld! Here is a secret: =47=45=54=53=46=4c=41=47"
    decoded = quoted_printable_decode(encoded)
    assert decoded.startswith(b"Hello World! Here is a secret: GETSFLAG")


def test_qp_smart_decode() -> None:
    encoded = "Test=3DFlag=3D=47=45=54=53=46=4c=41=47{qp_smart}"
    res = smart_decode(encoded)
    assert "quoted_printable" in res
    assert "GETSFLAG{qp_smart}" in res["quoted_printable"]
