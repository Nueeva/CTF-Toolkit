from ctf_toolkit.reversing.charcodes import decode_charcodes, encode_charcodes


def test_decode_charcodes_list():
    codes = [71, 69, 84, 83]
    assert decode_charcodes(codes) == "GETS"


def test_decode_charcodes_str():
    raw_js = "const a = [71, 69, 84, 83, 70, 76, 65, 71];"
    assert decode_charcodes(raw_js) == "GETSFLAG"


def test_encode_charcodes():
    text = "GETS"
    assert encode_charcodes(text) == [71, 69, 84, 83]
