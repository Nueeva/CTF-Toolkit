from ctf_toolkit.osint_misc.config_hunter import extract_ini_secrets


def test_extract_ini_secrets() -> None:
    ini_doc = """
    [general]
    name = demo
    debug = false

    [auth]
    user = admin
    token = GETSFLAG{test_ini_field}

    [cache]
    ttl = 60
    """
    findings = extract_ini_secrets(ini_doc)
    assert any("auth.token" in path and "GETSFLAG{test_ini_field}" in val for path, val in findings)


def test_extract_ini_empty() -> None:
    ini_doc = """
    [general]
    app = hello
    version = 1.0
    """
    findings = extract_ini_secrets(ini_doc)
    assert findings == []
