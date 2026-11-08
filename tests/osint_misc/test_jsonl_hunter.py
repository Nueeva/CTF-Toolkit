from ctf_toolkit.osint_misc.config_hunter import extract_jsonl_secrets


def test_extract_jsonl_secrets() -> None:
    jsonl_sample = (
        '{"id": 1, "user": "alice", "log": "logged in"}\n'
        '{"id": 2, "user": "bob", "log": "secret token: GETSFLAG{mca_jsonl_needle}"}\n'
        '{"id": 3, "user": "charlie", "log": "logged out"}\n'
    )
    secrets = extract_jsonl_secrets(jsonl_sample)
    assert len(secrets) == 1
    assert secrets[0]["secret"] == "GETSFLAG{mca_jsonl_needle}"
    assert secrets[0]["line"] == "2"


def test_extract_jsonl_empty() -> None:
    assert extract_jsonl_secrets("") == []
