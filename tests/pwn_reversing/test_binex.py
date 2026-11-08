from ctf_toolkit.binex.pwncalc import cyclic_create, cyclic_find


def test_cyclic_roundtrip():
    pattern = cyclic_create(100)
    needle = pattern[32:36]
    assert cyclic_find(needle) == 32
