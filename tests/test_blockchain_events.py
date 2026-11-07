from ctf_toolkit.blockchain.events import decode_event_log_data


def test_decode_event_log_data():
    raw_data = "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000568656c6c6f000000000000000000000000000000000000000000000000000000"
    res = decode_event_log_data(raw_data)
    assert res["word_count"] == 3
    assert "hello" in res["extracted_strings"]
