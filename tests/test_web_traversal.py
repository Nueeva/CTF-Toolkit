from ctf_toolkit.web.traversal import check_lfi_disclosure, generate_traversal_payloads


def test_generate_traversal_payloads():
    payloads = generate_traversal_payloads("flag.txt", depth=3)
    assert "flag.txt" in payloads
    assert "/flag.txt" in payloads
    assert "../../../flag.txt" in payloads
    assert "%2e%2e%2fflag.txt" in payloads
    assert "....//flag.txt" in payloads


def test_check_lfi_disclosure():
    res_flag = check_lfi_disclosure("Congrats! Flag is GETSFLAG{test_lfi_123}")
    assert res_flag["disclosed"] is True
    assert res_flag["flag"] == "GETSFLAG{test_lfi_123}"

    res_passwd = check_lfi_disclosure("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:...")
    assert res_passwd["disclosed"] is True
    assert res_passwd["is_passwd"] is True
