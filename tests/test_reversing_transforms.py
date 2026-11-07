from ctf_toolkit.reversing.transforms import endian_swap, reverse_string


def test_reverse_string():
    assert reverse_string("}cba{FTC") == "CTF{abc}"


def test_endian_swap():
    # 'ABCD' -> 'DCBA'
    data = b"ABCD1234"
    assert endian_swap(data, 4) == b"DCBA4321"
