from ctf_toolkit.osint_misc.config_hunter import extract_csv_secrets


def test_extract_csv_secrets() -> None:
    csv_doc = """id,name,role,note
1,ani,ops,ok
2,budi,dev,GETSFLAG{test_csv_secret}
3,citra,qa,ok
"""
    findings = extract_csv_secrets(csv_doc)
    flags = [val for _, val in findings if "GETSFLAG" in val]
    assert "GETSFLAG{test_csv_secret}" in flags


def test_extract_csv_no_secrets() -> None:
    csv_doc = """id,name,role
1,ani,ops
2,budi,dev
"""
    findings = extract_csv_secrets(csv_doc)
    assert findings == []
