from ctf_toolkit.forensics.pyc_decompile import extract_pyc_constants_raw


def test_extract_pyc_constants_raw_base32() -> None:
    # Synthetic pyc fragment containing Base32 encoded token
    dummy_pyc = (
        b"\x6f\r\r\n\x00\x00\x00\x00"
        b"\xe3\x00\x00\x00"
        b"I5CVIU2GJRAUO63QPFRV6YTBONSTGMS7MNXW443UPU======"
        b"\x00\x00"
    )
    extracted = extract_pyc_constants_raw(dummy_pyc)
    assert "GETSFLAG{pyc_base32_const}" in extracted


def test_extract_pyc_constants_raw_base64() -> None:
    # Synthetic fragment containing Base64 encoded token
    # R0VUU0ZMQUd7cHljX2Jhc2U2NF9jb25zdH0= -> GETSFLAG{pyc_base64_const}
    dummy_pyc = (
        b"\x6f\r\r\n\x00\x00\x00\x00"
        b"R0VUU0ZMQUd7cHljX2Jhc2U2NF9jb25zdH0="
        b"\x00\x00"
    )
    extracted = extract_pyc_constants_raw(dummy_pyc)
    assert "GETSFLAG{pyc_base64_const}" in extracted
