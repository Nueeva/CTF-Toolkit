from ctf_toolkit.reversing.transforms import extract_binary_strings


def test_extract_binary_strings():
    data = b"\x00\x00\x00Hello CTF World!\x00\xff\xfeGETSFLAG{hardcoded_test_flag}\x00"
    strings = extract_binary_strings(data, min_length=4)
    assert "Hello CTF World!" in strings
    assert "GETSFLAG{hardcoded_test_flag}" in strings

    flag_matches = extract_binary_strings(data, pattern=r"GETSFLAG\{")
    assert len(flag_matches) == 1
    assert flag_matches[0] == "GETSFLAG{hardcoded_test_flag}"
